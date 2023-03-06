package tenjin

import future.keywords

# This request will fail as the group is empty
test_denied_hdc_group if {
	not allow with input as {
		"groups": "",
		"object": "secrets",
		"scope": "qa1",
		"subject": "hdc",
		"verb": "GET",
	}
}

# This request will fail as the object is not configurations or secrets 
test_denied_hdc_object if {
	not allow with input as {
		"groups": "svc-hdc-developer@abc.com",
		"object": "config",
		"scope": "qa1",
		"subject": "hdc",
		"verb": "GET",
	}
}

# This request will fail as the scope is not one of qa1, qa2 or production
test_denied_hdc_scope if {
	not allow with input as {
		"groups": "svc-hdc-developer@abc.com",
		"object": "secrets",
		"scope": "qa3",
		"subject": "hdc",
		"verb": "GET",
	}
}

# This request will fail as the subject is empty
test_denied_hdc_subject if {
	not allow with input as {
		"groups": "svc-hdc-developer@abc.com",
		"object": "secrets",
		"scope": "qa1",
		"subject": "",
		"verb": "GET",
	}
}

# This request will fail as the verb is empty
test_denied_hdc_verb if {
	not allow with input as {
		"groups": "svc-hdc-developer@abc.com",
		"object": "secrets",
		"scope": "qa1",
		"subject": "hdc",
		"verb": "",
	}
}

# This request will pass
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
