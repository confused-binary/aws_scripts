if [[ $# -eq 0 ]]; then echo "Error: Pass profile name"; exit; fi
prof=$1
account=$(aws --profile ${prof} sts get-caller-identity | jq -r '.Account')

# Get list of role names
echo "account;role;policy_name;actions;resources"
for role in $(aws --profile ${prof} iam list-roles | jq -r '.Roles[].RoleName'); do
	# Get list of attached policy ARNs for each role
	policy_names=($(aws --profile ${prof} iam list-role-policies --role-name ${role} | jq -r '.PolicyNames[]'))
	for policy_name in ${policy_names[@]}; do
		# Get default policy version
		policy_data=$(aws --profile ${prof} iam get-role-policy --role-name ${role} --policy-name ${policy_name})

		statement_length=$(echo ${policy_data} | jq -r '.PolicyDocument.Statement | length')
		# Sometimes it's an object - not sure why
		type=$(echo ${policy_data} | jq -r '.PolicyDocument.Statement | type')
		[[ "${type}" == "object" ]] && statement_length=1
		count=0
		while [ "${count}" -lt "${statement_length}" ]; do
			action_status="False"
			resource_status="False"
			if [[ "${type}" == "object" ]]; then
				action_data=$(echo ${policy_data} | jq -cr '.PolicyDocument.Statement.Action')
				resource_data=$(echo ${policy_data} | jq -cr '.PolicyDocument.Statement.Resource')
			else
				action_data=$(echo ${policy_data} | jq --argjson count $count -cr '.PolicyDocument.Statement[$count].Action')
				resource_data=$(echo ${policy_data} | jq --argjson count $count -cr '.PolicyDocument.Statement[$count].Resource')
			fi
			# Check for PassRole Actions
			action=$(echo ${action_data} | grep -Eio "\"\*|iam:\*|iam:Pass\*|iam:\*Role|iam:PassRole")
			resource=$(echo "${resource_data}" | grep -Eio "\"\*|[a-z].*:[a-z].*:[a-z0-9].*:[0-9]*12:.*\*")
			if [[ "${action_data}" == "*" ]]; then
				action_status="True"
				action=${action_data}
			elif [[ ! -z ${action} ]]; then
				action_status="True"
			fi
			# Check for wide Rescources
			if [[ "${resource_data}" == "*" ]]; then
				resource_status="True"
				resource=${resource_data}
			elif [[ ! -z ${resource} ]]; then
				resource_status="True"
			fi
	
			if [ "${action_status}" == "True" ] && [ "${resource_status}" == "True" ]; then
				echo "${account};${role};${policy_name};${action};${resource}"
			fi
			
			count=$(( ${count} + 1 ))
		done
	done
done
