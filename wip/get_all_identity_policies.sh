profiles=$(aws configure list-profiles | grep "${ENG}")
get_all_versions=False
scope_local_only=False

for prof in ${profiles[@]}; do

	profile_dir="${ENG_HOME}/iam/all_iam_policies_${prof}"
	[[ ! -d "${profile_dir}" ]] && mkdir ${profile_dir}
	[[ -f "${profile_dir}/policy_use.csv" ]] && rm ${profile_dir}/policy_use.csv

	# Get Users if needed
	if [[ ! -f "${profile_dir}/iam_users_all_${prof}.json" ]]; then
		echo "# User json not found. Getting with profile."
		aws --profile ${prof} iam list-users > ${profile_dir}/iam_users_all_${prof}.json
	fi

	# Get user policies
	for user in $(cat ${profile_dir}/iam_users_all_${prof}.json | jq -cr '.Users[].UserName'); do
		# Attached Managed Policy
		attached=$(aws --profile ${prof} iam list-attached-user-policies --user-name ${user} | jq -cr '.AttachedPolicies')
		for policy in $(echo ${attached} | jq -cr '.[]'); do
			policy_data=$(aws --profile ${prof} iam get-policy --policy-arn $(echo $policy | jq -r '.PolicyArn') | jq -cr '.Policy')
			policy_arn=$(echo ${policy_data} | jq -cr '.Arn')
			policy_version=$(echo ${policy_data} | jq -cr '.DefaultVersionId' | sed 's_v__')
			policy_name=$(echo ${policy_data} | jq -r '.PolicyName')
			exit

			scope="Local"
			[[ "${policy_arn}" =~ ^"arn:aws:iam::aws:".* ]] && scope="AWS"
			[[ "${scope_local_only}" == "True" ]] && [[ "${scope}" == "AWS" ]] && continue

			aws --profile ${prof} iam get-policy-version --policy-arn ${policy_arn} --version-id v${policy_version} > ${profile_dir}/${scope}_${policy_name}_${policy_version}.json
		echo "user,${user},${scope},${policy_name},${policy_version}" | tee -a ${profile_dir}/policy_use.csv

			if [[ "${get_all_versions}" == "True" ]] && [[ "${scope}" != "AWS" ]]; then
				while [[ "$(echo $policy_version | sed 's_v__')" -gt "1" ]]; do
					policy_version=$(( ${policy_version} - 1 ))
					aws --profile ${prof} iam get-policy-version --policy-arn ${policy_arn} --version-id v${policy_version} > ${profile_dir}/${scope}_${policy_name}_${policy_version}.json
				echo "user,${user},${scope},${policy_name},${policy_version}" | tee -a ${profile_dir}/policy_use.csv
				done
			fi
		done

		# Attached Inline Policy
		inline=$(aws --profile ${prof} iam list-user-policies --user-name ${user} | jq -cr '.PolicyNames')
		for policy in $(echo ${inline} | jq -cr '.[]'); do
			aws --profile ${prof} iam get-user-policy --user-name ${user} --policy-name ${policy} | jq -r '.PolicyDocument.Statement' > ${profile_dir}/inline_${user}_${policy}.json
			echo "user,${user},Inline,${policy},1" | tee -a ${profile_dir}/policy_use.csv
		done
	done

	# Get Groups if needed
	if [[ ! -f "${profile_dir}/iam_groups_all_${prof}.json" ]]; then
		echo "# Group json not found. Getting with profile."
		aws --profile ${prof} iam list-groups > ${profile_dir}/iam_groups_all_${prof}.json
	fi

	for group in $(cat ${profile_dir}/iam_groups_all_${prof}.json | jq -cr '.Groups[].GroupName'); do
		# Attached Managed Policy
		attached=$(aws --profile ${prof} iam list-attached-group-policies --group-name ${group} | jq -cr '.AttachedPolicies')
		for policy in $(echo ${attached} | jq -cr '.[]'); do
			policy_data=$(aws --profile ${prof} iam get-policy --policy-arn $(echo $policy | jq -r '.PolicyArn') | jq -cr '.Policy')
			policy_arn=$(echo ${policy_data} | jq -cr '.Arn')
			policy_version=$(echo ${policy_data} | jq -cr '.DefaultVersionId' | sed 's_v__')
			policy_name=$(echo ${policy_data} | jq -r '.PolicyName')

			scope="Local"
			[[ "${policy_arn}" =~ ^"arn:aws:iam::aws:".* ]] && scope="AWS"
			[[ "${scope_local_only}" == "True" ]] && [[ "${scope}" == "AWS" ]] && continue

			aws --profile ${prof} iam get-policy-version --policy-arn ${policy_arn} --version-id v${policy_version} > ${profile_dir}/${scope}_${policy_name}_${policy_version}.json
		echo "group,${group},${scope},${policy_name},${policy_version}" | tee -a ${profile_dir}/policy_use.csv

			if [[ "${get_all_versions}" == "True" ]] && [[ "${scope}" != "AWS" ]]; then
				while [[ "$(echo $policy_version | sed 's_v__')" -gt "1" ]]; do
					policy_version=$(( ${policy_version} - 1 ))
					aws --profile ${prof} iam get-policy-version --policy-arn ${policy_arn} --version-id v${policy_version} > ${profile_dir}/${scope}_${policy_name}_${policy_version}.json
				echo "group,${group},${scope},${policy_name},${policy_version}" | tee -a ${profile_dir}/policy_use.csv
				done
			fi
		done

		# Attached Inline Policy
		inline=$(aws --profile ${prof} iam list-group-policies --group-name ${group} | jq -cr '.PolicyNames')
		for policy in $(echo ${inline} | jq -cr '.[]'); do
			aws --profile ${prof} iam get-group-policy --group-name ${group} --policy-name ${policy} | jq -r '.PolicyDocument.Statement' > ${profile_dir}/inline_${group}_${policy}.json
			echo "group,${group},Inline,${policy},1" | tee -a ${profile_dir}/policy_use.csv
		done
	done

	# Get Roles if needed
	if [[ ! -f "${profile_dir}/iam_roles_all_${prof}.json" ]]; then
		echo "# Role json not found. Getting with profile."
		aws --profile ${prof} iam list-roles > ${profile_dir}/iam_roles_all_${prof}.json
	fi

	# Get role policies
	for role in $(cat ${profile_dir}/iam_roles_all_${prof}.json | jq -cr '.Roles[].RoleName'); do
		# Attached Managed Policy
		attached=$(aws --profile ${prof} iam list-attached-role-policies --role-name ${role} | jq -cr '.AttachedPolicies')
		for policy in $(echo ${attached} | jq -cr '.[]'); do
		policy_data=$(aws --profile ${prof} iam get-policy --policy-arn $(echo $policy | jq -r '.PolicyArn') | jq -cr '.Policy')
			policy_arn=$(echo ${policy_data} | jq -cr '.Arn')
			policy_version=$(echo ${policy_data} | jq -cr '.DefaultVersionId' | sed 's_v__')
			policy_name=$(echo ${policy_data} | jq -r '.PolicyName')

			scope="Local"
			[[ "${policy_arn}" =~ ^"arn:aws:iam::aws:".* ]] && scope="AWS"
			[[ "${scope_local_only}" == "True" ]] && [[ "${scope}" == "AWS" ]] && continue

			aws --profile ${prof} iam get-policy-version --policy-arn ${policy_arn} --version-id v${policy_version} > ${profile_dir}/${scope}_${policy_name}_${policy_version}.json
		echo "role,${role},${scope},${policy_name},${policy_version}" | tee -a ${profile_dir}/policy_use.csv

			if [[ "${get_all_versions}" == "True" ]] && [[ "${scope}" != "AWS" ]]; then
				while [[ "$(echo $policy_version | sed 's_v__')" -gt "1" ]]; do
					policy_version=$(( ${policy_version} - 1 ))
					aws --profile ${prof} iam get-policy-version --policy-arn ${policy_arn} --version-id v${policy_version} > ${profile_dir}/${scope}_${policy_name}_${policy_version}.json
				echo "role,${role},${scope},${policy_name},${policy_version}" | tee -a ${profile_dir}/policy_use.csv
				done
			fi
		done

		# Attached Inline Policy
		inline=$(aws --profile ${prof} iam list-role-policies --role-name ${role} | jq -cr '.PolicyNames')
		for policy in $(echo ${inline} | jq -cr '.[]'); do
			aws --profile ${prof} iam get-role-policy --role-name ${role} --policy-name ${policy} | jq -r '.PolicyDocument.Statement' > ${profile_dir}/inline_${role}_${policy}.json
			echo "role,${role},Inline,${policy},1" | tee -a ${profile_dir}/policy_use.csv
		done
	done
done