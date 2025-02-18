# get ecs services/tasks along with LBs and task definition

echo "account;cluster;service;container;dns;ip;port"
for PROF in $(aws configure list-profiles | grep ${ENG}); do
	account=$(aws --profile ${PROF} sts get-caller-identity | jq -r '.Account')
	clusters=$(aws --profile ${PROF} ecs list-clusters | jq -r '.clusterArns[]')
	for cluster in ${clusters[@]}; do
		cluster_name=$(aws --profile ${PROF} ecs describe-clusters --cluster ${cluster} | jq -cr '.clusters[].clusterName')

		services=$(aws --profile ${PROF} ecs list-services --cluster ${cluster_name} | jq -cr '.serviceArns[]')
		declare -A service_details
		for service in ${services[@]}; do
			details=$(aws --profile ${PROF} ecs describe-services --cluster ${cluster_name} --service ${service} | jq -cr '.services[]')
			svc_name=$(echo ${details} | jq -cr '.serviceName')
			c_name=$(echo ${details} | jq -cr '.loadBalancers[].containerName')
			port=$(echo ${details} | jq -cr '.loadBalancers[].containerPort')
			service_details+=( [${c_name}]="${port},${svc_name}" )
		done

		tasks=$(aws --profile ${PROF} ecs list-tasks --cluster ${cluster} | jq -cr '.taskArns[]')
		for task in ${tasks[@]}; do
			details=$(aws --profile ${PROF} ecs describe-tasks --cluster ${cluster} --task ${task} | jq -cr '.tasks[]')
			private_ipv4=$(echo ${details} | jq -cr '.attachments[].details[] | select(.name == "privateIPv4Address") | .value')
			private_dns=$(echo ${details} | jq -cr '.attachments[].details[] | select(.name == "privateDnsName") | .value')
			c_name=$(echo ${details} | jq -cr '.containers[].name')
			port=$(echo ${service_details[${c_name}]} | cut -d',' -f1)
			svc_name=$(echo ${service_details[${c_name}]} | cut -d',' -f2)
	
			echo "${account};${cluster_name};${svc_name};${c_name};${private_dns};${private_ipv4};${port}"
		done
	done
done
