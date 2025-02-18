if [[ $# -eq 0 ]]; then echo "Error: Pass profile name"; exit; fi
prof=$1
account=$(aws --profile ${prof} sts get-caller-identity | jq -r '.Account')

# Get list of group names
#echo "account;group;policy_name;actions;resources"
for group in $(aws --profile ${prof} iam list-groups | jq -r '.Groups[].GroupName'); do
	# Get list of attached policy ARNs fo reach group
	policy_arns=($(aws --profile ${prof} iam list-attached-group-policies --group-name ${group} | jq -r '.AttachedPolicies[].PolicyArn'))
	for arn in ${policy_arns[@]}; do
		policy_name=$(echo ${arn} | cut -d'/' -f2)
		# Get default policy version
		policy_version=$(aws --profile ${prof} iam get-policy --policy-arn ${arn} | jq -r '.Policy.DefaultVersionId')
		# Get policy data
		policy_data=$(aws --profile ${prof} iam get-policy-version --policy-arn ${arn} --version-id ${policy_version})

		statement_length=$(echo ${policy_data} | jq -r '.PolicyVersion.Document.Statement | length')
		count=0
		while [ "${count}" -lt "${statement_length}" ]; do
			action_status="False"
			resource_status="False"
			action_data=$(echo ${policy_data} | jq --argjson count $count -cr '.PolicyVersion.Document.Statement[$count].Action')
			resource_data=$(echo ${policy_data} | jq --argjson count $count -cr '.PolicyVersion.Document.Statement[$count].Resource')
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
				echo "${account};${group};${policy_name};${action};${resource}"
			fi
			
			count=$(( ${count} + 1 ))
		done
	done
done
