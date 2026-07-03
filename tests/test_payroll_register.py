import datetime
import sqlite3

import server as server_module
from conftest import signup, create_company


def make_company(client):
    signup(client)
    return create_company(client).get_json()["id"]


def _get_company_row(cid):
    db = sqlite3.connect(server_module.DB_PATH)
    db.row_factory = sqlite3.Row
    row = db.execute("SELECT * FROM companies WHERE id = ?", (cid,)).fetchone()
    db.close()
    return row


# ---------- calculate_paye_ni: Employment Allowance + student loan ----------

def test_employment_allowance_reduces_employer_ni_up_to_the_remaining_cap():
    rates = server_module.DEFAULT_PAYROLL_RATES
    result = server_module.calculate_paye_ni(3000, "monthly", rates, employment_allowance_remaining=100)
    assert result["employmentAllowanceUsed"] == 100
    full = server_module.calculate_paye_ni(3000, "monthly", rates)
    assert result["employerNi"] == round(full["employerNi"] - 100, 2)


def test_employment_allowance_caps_at_remaining_amount_not_full_ni():
    rates = server_module.DEFAULT_PAYROLL_RATES
    full = server_module.calculate_paye_ni(3000, "monthly", rates)
    result = server_module.calculate_paye_ni(3000, "monthly", rates, employment_allowance_remaining=full["employerNi"] + 500)
    assert result["employmentAllowanceUsed"] == full["employerNi"]  # can't use more than the NI actually due
    assert result["employerNi"] == 0


def test_student_loan_plan2_deduction_above_threshold():
    rates = server_module.DEFAULT_PAYROLL_RATES
    annual_gross = 40000
    result = server_module.calculate_paye_ni(annual_gross / 12, "monthly", rates, student_loan_plan="plan2")
    expected_annual = (annual_gross - rates["studentLoanPlan2Threshold"]) * rates["studentLoanRate"] / 100
    assert result["studentLoan"] == round(expected_annual / 12, 2)


def test_student_loan_no_deduction_below_threshold():
    rates = server_module.DEFAULT_PAYROLL_RATES
    result = server_module.calculate_paye_ni(1500, "monthly", rates, student_loan_plan="plan2")  # 18k/year, below 27,295
    assert result["studentLoan"] == 0


def test_student_loan_plan_plus_postgrad_stacks_both_deductions():
    rates = server_module.DEFAULT_PAYROLL_RATES
    annual_gross = 40000
    combined = server_module.calculate_paye_ni(annual_gross / 12, "monthly", rates, student_loan_plan="plan2+postgrad")
    plan_only = server_module.calculate_paye_ni(annual_gross / 12, "monthly", rates, student_loan_plan="plan2")
    postgrad_only = server_module.calculate_paye_ni(annual_gross / 12, "monthly", rates, student_loan_plan="postgrad")
    assert combined["studentLoan"] == round(plan_only["studentLoan"] + postgrad_only["studentLoan"], 2)


# ---------- employee register CRUD + run_payroll_for_company ----------

def test_create_and_list_employee(client):
    cid = make_company(client)
    res = client.post(f"/api/companies/{cid}/employees", json={
        "name": "Jane Doe", "payFrequency": "monthly", "grossPay": 3000, "nextPayDate": "2020-01-01",
    })
    assert res.status_code == 200
    employees = client.get(f"/api/companies/{cid}/employees").get_json()
    assert len(employees) == 1
    assert employees[0]["name"] == "Jane Doe"
    assert employees[0]["grossPay"] == 3000


def test_run_payroll_posts_journal_and_advances_next_pay_date(client):
    cid = make_company(client)
    client.post(f"/api/companies/{cid}/employees", json={
        "name": "Jane Doe", "payFrequency": "monthly", "grossPay": 3000, "nextPayDate": "2020-01-01",
    })
    company = _get_company_row(cid)
    db = sqlite3.connect(server_module.DB_PATH)
    db.row_factory = sqlite3.Row
    result = server_module.run_payroll_for_company(db, company)
    assert len(result["posted"]) == 1
    assert result["posted"][0]["name"] == "Jane Doe"

    txs = client.get(f"/api/companies/{cid}/transactions").get_json()
    assert len(txs) > 0  # net pay / PAYE / NI / pension legs all posted

    employees = client.get(f"/api/companies/{cid}/employees").get_json()
    assert employees[0]["nextPayDate"] == "2020-02-01"  # advanced by one month
    db.close()


def test_run_payroll_is_a_no_op_before_next_pay_date_arrives(client):
    cid = make_company(client)
    future_date = "2099-01-01"
    client.post(f"/api/companies/{cid}/employees", json={
        "name": "Jane Doe", "payFrequency": "monthly", "grossPay": 3000, "nextPayDate": future_date,
    })
    company = _get_company_row(cid)
    db = sqlite3.connect(server_module.DB_PATH)
    db.row_factory = sqlite3.Row
    result = server_module.run_payroll_for_company(db, company)
    assert result["posted"] == []
    employees = client.get(f"/api/companies/{cid}/employees").get_json()
    assert employees[0]["nextPayDate"] == future_date  # unchanged
    db.close()


def test_run_payroll_second_run_same_period_does_not_double_post(client):
    cid = make_company(client)
    today = datetime.date.today().isoformat()
    client.post(f"/api/companies/{cid}/employees", json={
        "name": "Jane Doe", "payFrequency": "monthly", "grossPay": 3000, "nextPayDate": today,
    })
    company = _get_company_row(cid)
    db = sqlite3.connect(server_module.DB_PATH)
    db.row_factory = sqlite3.Row
    server_module.run_payroll_for_company(db, company)
    company_after = _get_company_row(cid)
    second = server_module.run_payroll_for_company(db, company_after)
    assert second["posted"] == []  # next_pay_date already advanced a month past today, not due again
    db.close()


def test_inactive_employee_is_skipped_by_payroll_run(client):
    cid = make_company(client)
    emp_id = client.post(f"/api/companies/{cid}/employees", json={
        "name": "Jane Doe", "payFrequency": "monthly", "grossPay": 3000, "nextPayDate": "2020-01-01",
    }).get_json()["id"]
    client.put(f"/api/companies/{cid}/employees/{emp_id}", json={"active": False})
    company = _get_company_row(cid)
    db = sqlite3.connect(server_module.DB_PATH)
    db.row_factory = sqlite3.Row
    result = server_module.run_payroll_for_company(db, company)
    assert result["posted"] == []
    db.close()


def test_delete_employee(client):
    cid = make_company(client)
    emp_id = client.post(f"/api/companies/{cid}/employees", json={
        "name": "Jane Doe", "payFrequency": "monthly", "grossPay": 3000, "nextPayDate": "2020-01-01",
    }).get_json()["id"]
    res = client.delete(f"/api/companies/{cid}/employees/{emp_id}")
    assert res.status_code == 200
    assert client.get(f"/api/companies/{cid}/employees").get_json() == []


# ---------- automatic depreciation ----------

def test_run_depreciation_for_company_posts_for_every_asset(client):
    cid = make_company(client)
    client.post(f"/api/companies/{cid}/fixed-assets", json={
        "name": "Laptop", "assetAccount": "Fixed Assets", "cost": 1200,
        "purchaseDate": "2020-01-01", "usefulLifeYears": 3,
    })
    company = _get_company_row(cid)
    db = sqlite3.connect(server_module.DB_PATH)
    db.row_factory = sqlite3.Row
    result = server_module.run_depreciation_for_company(db, company)
    assert len(result["posted"]) == 1
    assert result["posted"][0]["name"] == "Laptop"
    db.close()


def test_run_depreciation_for_company_skips_asset_already_posted_today(client):
    cid = make_company(client)
    client.post(f"/api/companies/{cid}/fixed-assets", json={
        "name": "Laptop", "assetAccount": "Fixed Assets", "cost": 1200,
        "purchaseDate": "2020-01-01", "usefulLifeYears": 3,
    })
    company = _get_company_row(cid)
    db = sqlite3.connect(server_module.DB_PATH)
    db.row_factory = sqlite3.Row
    server_module.run_depreciation_for_company(db, company)
    second = server_module.run_depreciation_for_company(db, company)
    assert second["posted"] == []
    assert len(second["skipped"]) == 1
    db.close()
