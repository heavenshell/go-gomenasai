"scope" {
    start = "2015-04-01 00:00:00 +0900" // +0900 is JST
    end = "2015-04-02 00:00:00 +0900"   // +0900 is JST
    affected = "Database, Mailserver"
}

"breach" {
    address = false
    name = false
    gender = false
    birthday = false
    tel = false
    card = false
    securitycode = false
    token = false
    defaced_malware = true
}

"web" {
  endpoint = "/security-incident"
}
