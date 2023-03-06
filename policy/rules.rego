package tenjin

import future.keywords

default allow = false

eng_group := "engineering@abc.com"

# Allows or denies actions based on comparison between input and data
allow if {
	role := data.components[input.subject][input.object][input.verb][input.scope]
	role == "engineer"
	eng_group in input.groups
}

allow if {
	role := data.components[input.subject][input.object][input.verb][input.scope]
	role != "engineer"
	data.components[input.subject][roles][role] in input.groups
}

# Errors if object is other than configurations or secrets
error contains msg if {
	not input.object in ["configurations", "secrets"]
	msg := "Only configurations or secrets are allowed as objects"
}

# Errors if scope is other than qa1, qa2 and production
error contains msg if {
	not input.scope in ["qa1", "qa2", "production"]
	msg := "Only qa1, qa2 and production are allowed as scopes"
}

# Errors if verb is other than access, get, list, create, update, updatevalue, delete
error contains msg if {
	input.object == "secrets"
	not input.verb in ["ACCESS", "CREATE", "DELETE", "GET", "LIST", "UPDATE", "UPDATEVALUE"]
	msg := "Only 'ACCESS', 'CREATE', 'DELETE', 'GET', 'LIST', 'UPDATE', 'UPDATEVALUE' are allowed as verbs for secrets"
}

# Errors if verb is other than get, list, create, update, updatevalue, delete
error contains msg if {
	input.object == "configurations"
	not input.verb in ["CREATE", "DELETE", "GET", "LIST", "UPDATE"]
	msg := "Only 'CREATE', 'DELETE', 'GET', 'LIST', 'UPDATE' are allowed as verbs for configurations"
}

# Errors if group is empty
error contains msg if {
	input.groups == ""
	msg := "Group cannot be empty and no action is allowed"
}

# Errors if subject is not one of the defined services
error contains msg if {
	not input.subject in ["hdc", "cps", "mono", "e9y"]
	msg := "Only 'hdc', 'cps', 'mono', 'e9y' services are allowed as subjects"
}

# Errors if users with insufficient priveleges perform unauthorized actions 
error contains msg if {
	input.verb in ["CREATE", "UPDATE", "DELETE"]
	role := data.components[input.subject][input.object][input.verb][input.scope]
	not role in ["engineer", "developer"]
	input.scope == "production"
	msg := "only an owner is allowed to perform this action"
}


