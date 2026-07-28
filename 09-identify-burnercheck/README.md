# burner_number_check

Flask app that classifies a US phone number as a burner / VoIP / real mobile / landline using two signals:

1. **CSV lookup** — NPA-NXX block assignment from `CoCodeAssignment_Utilized_AllStates_Public.txt` (FCC/NANPA company codes), matched against burner-carrier keywords (Bandwidth, Onvoy, Level 3, Vonage, Telnyx, Commio, Pinger, TextNow, Google, Peerless, SVR, CLEC).
2. **Twilio Lookup v2** — `line_type_intelligence` to get the live `carrier_name` and `line_type` (mobile / nonFixedVoip / landline / etc.). `nonFixedVoip` is treated as a burner.

Each query is appended to `phone_analysis_history.json`.

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env
# fill in TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN
python burner_check.py
```

The CSV file `CoCodeAssignment_Utilized_AllStates_Public.txt` is not bundled — download it from the NANPA Co Code data export and place it next to `burner_check.py`.

## Files

- `burner_check.py` — Flask UI + CSV/Twilio classifiers
- `phone_analysis_history.json` — query history
- `burner_check.pdf` — write-up
- `.env.example` — template for Twilio credentials
