import datetime

import server as server_module


def test_ct_payment_deadline_surfaces_within_30_days():
    company = {"entity_type": "limited_company", "period_start_date": "2020-04-01"}
    # FY ended 2026-03-31 -> CT payment due 2027-01-01 (9 months + 1 day later)
    today = datetime.date(2026, 12, 20)
    deadlines = server_module.compute_statutory_deadlines(company, today)
    labels = [d["label"] for d in deadlines]
    assert any("Corporation Tax payment" in l for l in labels)
    payment = next(d for d in deadlines if "payment" in d["label"])
    assert payment["due"] == "2027-01-01"


def test_ct600_filing_deadline_surfaces_within_30_days():
    company = {"entity_type": "limited_company", "period_start_date": "2020-04-01"}
    # FY ended 2026-03-31 -> CT600 filing due 2027-03-31 (12 months later)
    today = datetime.date(2027, 3, 5)
    deadlines = server_module.compute_statutory_deadlines(company, today)
    filing = next(d for d in deadlines if "CT600" in d["label"])
    assert filing["due"] == "2027-03-31"


def test_no_ct_deadlines_shown_outside_the_30_day_window():
    company = {"entity_type": "limited_company", "period_start_date": "2020-04-01"}
    today = datetime.date(2026, 7, 3)  # months away from either deadline
    assert server_module.compute_statutory_deadlines(company, today) == []


def test_self_assessment_deadline_for_sole_trader():
    company = {"entity_type": "sole_trader", "period_start_date": ""}
    today = datetime.date(2027, 1, 15)
    deadlines = server_module.compute_statutory_deadlines(company, today)
    assert len(deadlines) == 1
    assert deadlines[0]["due"] == "2027-01-31"
    assert "Self Assessment" in deadlines[0]["label"]


def test_self_assessment_rolls_to_next_year_after_deadline_passes():
    company = {"entity_type": "sole_trader", "period_start_date": ""}
    today = datetime.date(2027, 2, 1)  # just after this year's 31 Jan deadline
    deadlines = server_module.compute_statutory_deadlines(company, today)
    assert deadlines == []  # next deadline (31 Jan 2028) is far outside the 30-day window


def test_charity_gets_no_statutory_deadlines():
    company = {"entity_type": "charity", "period_start_date": "2020-04-01"}
    today = datetime.date(2026, 12, 20)
    assert server_module.compute_statutory_deadlines(company, today) == []


def test_limited_company_with_no_period_start_date_gets_no_ct_deadlines():
    company = {"entity_type": "limited_company", "period_start_date": ""}
    today = datetime.date(2026, 12, 20)
    assert server_module.compute_statutory_deadlines(company, today) == []
