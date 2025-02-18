if [[ $# -eq 0 ]]; then echo "Error: Pass profile name"; exit; fi
prof=$1
account=$(aws --profile ${prof} sts get-caller-identity | jq -r '.Account')

# Only functions with envs
function_data=$(aws --profile ${prof} lambda list-functions | jq -cr '.Functions | map(select(.Environment))')
function_len=$(echo ${function_data} | jq -cr '. | length')
count=0
while [[ "${count}" -lt "${function_len}" ]]; do
	function_name=$(echo ${function_data} | jq --argjson count $count -cr '.[$count].FunctionName')
	function_envs=$(echo ${function_data} | jq --argjson count $count -cr '.[$count].Environment.Variables')
	keys=($(echo ${function_envs} | jq '. | keys[]'))
	for key in ${keys[@]}; do 
		if [[ $(echo ${key} | grep -ie 'pass\|user\|akia\|asia\|aws.*key\|token') ]]; then
			value=$(echo ${function_envs} | jq -r '.' | grep "${key}" | cut -d: -f2 | sed 's_^ "__;s_"$__;s_",$__')
			echo "${account};${function_name};$(echo ${key} | sed 's_^"__;s_"$__'):${value}"
		fi
	done
	count=$(( ${count} + 1 ))
done
