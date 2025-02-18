# checks for the Users and Roles for:
#   Action: *
#   Action: iam:*
#   Action: iam:Put*
policy_regex="^[*]|^[iI][aA][mM]:\\*|^[iI][aA][mM]:[pP][uU][tT]\\*"
excluded_roles=("AWSControlTowerExecution", "AWSReservedSSO_", "aws-controltower-AdministratorExecutionRole")

profiles=$(aws configure list-profiles | grep "${ENG}")
echo "profile,acct,principal,source,status,policy"
for prof in ${profiles[*]}; do 
	acct=$(aws --profile "${prof}" sts get-caller-identity | jq -r '.Account')

	# Check users
	resp=$(aws --profile "${prof}" iam list-users)
	users=($(echo ${resp} | jq -r '.Users[].UserName'))
	marker=$(echo ${resp} | jq -r '. | if .Marker then .Marker else 0 end')

	while [[ "${marker}" != 0 ]]; do 
		resp=$(aws --profile "${prof}" iam list-users --starting-token "${marker}")
		users=("${users[*]}" "$(echo ${resp} | jq -r '.Users[].UserName')")
		marker=$(echo ${resp} | jq -r '. | if .Marker then .Marker else 0 end')
	done

	for user in ${users[@]}; do
		# Get user > policy
		attached_policies=($(aws --profile "${prof}" iam list-attached-user-policies --user-name "${user}" | jq -r '.AttachedPolicies[].PolicyArn'))

		for policy in ${attached_policies[*]}; do
			policy_version=$(aws --profile "${prof}" iam get-policy --policy-arn ${policy} | jq -r '.Policy.DefaultVersionId')
			policy_details=$(aws --profile "${prof}" iam get-policy-version --policy-arn ${policy} --version-id "${policy_version}")
			check=$(echo $policy_details | jq -re --arg policy_regex ${policy_regex} '.PolicyVersion.Document.Statement[] | select(.Action) | .Action | if type == "array" then .[] | test($policy_regex) else . | test($policy_regex) end' | grep true | head -1)
			if [[ "${check}" == "true" ]]; then
				echo "${prof},${acct},${user},[on-user],attached,${policy}"
			fi
		done

		user_policies=($(aws --profile "${prof}" iam list-user-policies --user-name "${user}" | jq -r '.PolicyNames[]'))
		for policy in ${user_policies[*]}; do
			policy_details=$(aws --profile "${prof}" iam get-user-policy --user-name "${user}" --policy-name "${policy}")
			check=$(echo $policy_details | jq -re --arg policy_regex ${policy_regex} '.PolicyVersion.Document.Statement[] | select(.Action) | .Action | if type == "array" then .[] | test($policy_regex) else . | test($policy_regex) end' | grep true | head -1)
			if [[ "${check}" == "true" ]]; then
				echo "${prof},${acct},${user},[on-user],inline,${policy}"
			fi
		done
        
		# Get user > group > policy
		resp=$(aws --profile "${prof}" iam list-groups-for-user --user-name "${user}")
		groups=($(echo ${resp} | jq -r '.Groups[].GroupName'))
		marker=$(echo ${resp} | jq -r '. | if .Marker then .Marker else 0 end')
		while [[ "${marker}" != 0 ]]; do 
			resp=$(aws --profile "${prof}" iam list-groups-for-user --user-name "${user}" --starting-token "${marker}")
			groups=("${groups[*]}" "$(echo ${resp} | jq -r '.Groups[].GroupName')")
			marker=$(echo ${resp} | jq -r '. | if .Marker then .Marker else 0 end')
		done

		for group in ${groups[@]}; do
			attached_policies=($(aws --profile "${prof}" iam list-attached-group-policies --group-name "${group}" | jq -r '.AttachedPolicies[].PolicyArn'))
			for policy in ${attached_policies[*]}; do
				policy_version=$(aws --profile "${prof}" iam get-policy --policy-arn ${policy} | jq -r '.Policy.DefaultVersionId')
				policy_details=$(aws --profile "${prof}" iam get-policy-version --policy-arn ${policy} --version-id "${policy_version}")
				check=$(echo $policy_details | jq -re --arg policy_regex ${policy_regex} '.PolicyVersion.Document.Statement[] | select(.Action) |.Action | if type == "array" then .[] | test($policy_regex) else . | test($policy_regex) end' | grep true | head -1)
				if [[ "${check}" == "true" ]]; then
					echo "${prof},${acct},${user},${group},attached,${policy}"
				fi
			done

			group_policies=($(aws --profile "${prof}" iam list-group-policies --group-name "${group}" | jq -r '.PolicyNames[]'))
			for policy in ${group_policies[*]}; do
				policy_data=$(aws --profile "${prof}" iam list-policies --only-attached | jq -r --arg policy $policy '.Policies[] | select(.PolicyName == $policy)')
				policy_arn=$(echo ${policy_data} | jq -r '.Arn')
				policy_version=$(echo ${policy_data} | jq -r '.DefaultVersionId')
				policy_details=$(aws --profile "${prof}" iam get-policy-version --policy-arn "${policy_arn}" --version-id "${policy_version}")
				check=$(echo $policy_details | jq -re --arg policy_regex ${policy_regex} '.PolicyVersion.Document.Statement[] | select(.Action) |.Action | if type == "array" then .[] | test($policy_regex) else . | test($policy_regex) end' | grep true | head -1)
				if [[ "${check}" == "true" ]]; then
					echo "${prof},${acct},${user},${group},inline,${policy}"
				fi
			done
		done
	done

	# Check Roles
	resp=$(aws --profile "${prof}" iam list-roles)
	roles=($(echo ${resp} | jq -r '.Roles[].RoleName'))
	marker=$(echo ${resp} | jq -r '. | if .Marker then .Marker else 0 end')
	while [[ "${marker}" != 0 ]]; do
		resp=$(aws --profile "${prof}" iam list-roles --starting-token "${marker}")
		roles=("${roles[*]}" "$(echo ${resp} | jq -r '.Roles[].RoleName')")
		marker=$(echo ${resp} | jq -r '. | if .Marker then .Marker else 0 end')
	done
	for role in ${roles[@]}; do
		for excluded_role in ${excluded_roles[@]}; do 
			# Skip role if in exclusions list
			if [[ -n $(echo ${excluded_role} | grep ${role}) ]]; then
				break
			fi
		done
		# Get role > policy
		attached_policies=($(aws --profile "${prof}" iam list-attached-role-policies --role-name "${role}" | jq -r '.AttachedPolicies[].PolicyArn'))
		for policy in ${attached_policies[*]}; do
			policy_version=$(aws --profile "${prof}" iam get-policy --policy-arn ${policy} | jq -r '.Policy.DefaultVersionId')
			policy_details=$(aws --profile "${prof}" iam get-policy-version --policy-arn ${policy} --version-id "${policy_version}")
			check=$(echo $policy_details | jq -re --arg policy_regex ${policy_regex} '.PolicyVersion.Document.Statement[] | select(.Action) | .Action | if type == "array" then .[] | test($policy_regex) else . | test($policy_regex) end' | grep true | head -1)
			if [[ "${check}" == "true" ]]; then
				echo "${prof},${acct},${role},[on-role],attached,${policy}"
			fi
		done

		role_policies=($(aws --profile "${prof}" iam list-role-policies --role-name "${role}" | jq -r '.PolicyNames[]'))
		for policy in ${role_policies[*]}; do
			policy_details=$(aws --profile "${prof}" iam get-role-policy --role-name "${role}" --policy-name "${policy}")
			check=$(echo $policy_details | jq -re --arg policy_regex ${policy_regex} '.PolicyDocument.Statement[] | select(.Action) | .Action | if type == "array" then .[] | test($policy_regex) else . | test($policy_regex) end' | grep true | head -1)
			if [[ "${check}" == "true" ]]; then
				echo "${prof},${acct},${role},[on-role],inline,${policy}"
			fi
		done
	done
done

echo "script finished" 2> /dev/null
