package acf.authz

default allow = false

allow {
    input.risk_score < 75
}