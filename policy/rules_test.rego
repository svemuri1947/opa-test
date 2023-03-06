test_allowed_hdc if {
	allow with input as {
		"groups": [
			"svc-hdc-developer@abc.com",
			"engineering@abc.com",
		],
		"object": "secrets",
		"scope": "qa1",
		"subject": "hdc",
		"verb": "CREATE",
	}
}
