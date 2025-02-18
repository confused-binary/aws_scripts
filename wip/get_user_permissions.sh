# get all user permissions in account
if [[ $# -eq 0 ]]; then echo "Error: Pass profile name"; exit; fi
PROF=$1
account=$(aws --profile ${PROF} sts get-caller-identity | jq -r '.Account')

users=$(aws --profile ${PROF} iam list-users | jq -r '.Users[].UserName')
for user in ${users[@]}; do
	inline_policies=$(aws --profile ${PROF} iam list-user-policies --user-name ${user} | jq -r '.PolicyNames[]')
	unset policy
	for policy in ${inline_policies[@]}; do
		echo "${account},${user},user,'',inlinePolicy,${policy}"
	done

	managed_policies=$(aws --profile ${PROF} iam list-attached-user-policies --user-name ${user} | jq -r '.AttachedPolicies[].PolicyName')
	unset policy
	for policy in ${managed_policies[@]}; do
		echo "${account},${user},user,'',managedPolicy,${policy}"
	done

	groups=$(aws --profile ${PROF} iam list-groups-for-user --user-name ${user} | jq -r '.Groups[].GroupName')
	for group in ${groups[@]}; do
		group_inline_policies=$(aws --profile ${PROF} iam list-group-policies --group-name ${group} | jq -r '.PolicyNames[].PolicyName')
		unset policy
		for policy in ${group_inline_policies[@]}; do
			echo "${account},${user},group,${group},inlinePolicy,${policy}"
		done

		group_managed_policies=$(aws --profile ${PROF} iam list-attached-group-policies --group-name ${group} | jq -r '.AttachedPolicies[].PolicyName')
		unset policy
		for policy in ${group_managed_policies[@]}; do
	        	echo "${account},${user},group,${group},managedPolicy,${policy}"
		done
	done
done
