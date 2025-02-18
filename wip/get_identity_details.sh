# get provided identity details and access
if [[ $# -eq 0 ]]; then echo "Error: Pass profile name"; exit; fi
PROF=$1
account=$(aws --profile ${PROF} sts get-caller-identity | jq -r '.Account')

arn=$(aws --profile ${PROF} sts get-caller-identity | jq -r '.Arn')
identity_type=$(echo ${arn} | cut -d':' -f6 | cut -d'/' -f1)
identity_name=$(echo ${arn} | cut -d':' -f6 | cut -d'/' -f2)
echo ${arn}
echo ${identity_type}
echo ${identity_name}

if [[ "${identity_type}" == "user" ]]; then
	managed_policies=$(aws --profile ${PROF} iam list-user-policies --user-name ${identity_name} | jq -r '.PolicyNames[].PolicyName')
	unset policy
	for policy in ${managed_policies[@]}; do
		echo "${PROF},${account},${identity_type},${identity_name},"",${policy}"
	done

	inline_policies=$(aws --profile ${PROF} iam list-attached-user-policies --user-name ${identity_name} | jq -r '.AttachedPolicies[].PolicyName')
	unset policy
	for policy in ${inline_policies[@]}; do
          echo "${PROF},${account},${identity_type},${identity_name},"",${policy}"
  done

	groups=$(aws --profile ${PROF} iam list-groups-for-user --user-name ${identity_name} | jq -r '.Groups[].GroupName')
	for group in ${groups[@]}; do
	        group_managed_policies=$(aws --profile ${PROF} iam list-group-policies --group-name ${group} | jq -r '.PolicyNames[].PolicyName')
		unset policy
		for policy in ${group_managed_policies[@]}; do
	                echo "${PROF},${account},${identity_type},${identity_name},${group},${policy}"
	        done

	        group_inline_policies=$(aws --profile ${PROF} iam list-attached-group-policies --group-name ${group} | jq -r '.AttachedPolicies[].PolicyName')
		unset policy
		for policy in ${group_inline_policies[@]}; do
	                echo "${PROF},${account},${identity_type},${identity_name},${group},${policy}"
	        done
	done
else
	managed_policies=$(aws --profile ${PROF} iam list-role-policies --role-name ${identity_name} | jq -r '.PolicyNames[].PolicyName')
	unset policy
	for policy in ${managed_policies[@]}; do
		echo "${PROF},${account},${identity_type},${identity_name},"",${policy}"
	done

	inline_policies=$(aws --profile ${PROF} iam list-attached-role-policies --role-name ${identity_name} | jq -r '.AttachedPolicies[].PolicyName')
	unset policy
	for policy in ${inline_policies[@]}; do
		echo "${PROF},${account},${identity_type},${identity_name},"",${policy}"
  	done
fi
