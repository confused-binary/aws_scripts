# Download and scan all ECR images

download_scan_delete () {
	repository=${1}
	img_tag=${2}

	echo "Downloading: ${repository}:${img_tag}"
	docker pull ${repository}:${img_tag}

	echo "Scanning: ${repository}:${img_tag}"
	trivy image ${repository}:${img_tag} --format json --severity HIGH,CRITICAL --output ${ENG_HOME}/ecr/$(echo ${repository} | sed 's|\/|--|g'):${img_tag}.trivy.json 2>&1 | tee -a ${ENG_HOME}/ecr/${account}.trivy.json
	
	echo "Removing: ${repository}:${img_tag}"
	docker rmi ${repository}:${img_tag}
}

n=1
total=$(aws configure list-profiles | grep "${ENG}" | wc -l)
mkdir -p ${ENG_HOME}/ecr/
for prof in $(aws configure list-profiles | grep "${ENG}"); do
	account=$(aws --profile ${prof} sts get-caller-identity | jq -r '.Account')
	regions=($(aws --profile ${prof} ec2 describe-regions | jq -r '.Regions[].RegionName'))
	for region in ${regions[@]}; do
		echo "[${n}/${total}] Profile ${prof} Region: ${region}"
		aws --profile ${prof} ecr get-login-password --region ${region} | docker login --username AWS --password-stdin ${account}.dkr.ecr.${region}.amazonaws.com
		repositories=$(aws --profile ${prof} --region ${region} ecr describe-repositories | jq -r '.repositories[].repositoryName' | sort -u)
		for repo in ${repositories[@]}; do
			repository="${account}.dkr.ecr.${region}.amazonaws.com/${repo}"
			echo "Repository: ${repository}"
			if [[ ${1} == "--all" ]]; then
				image_tags=($(aws --profile ${prof} --region ${region} ecr describe-images --repository-name ${repo} | jq -r '.imageDetails[].imageTags[]'))
				for img_tag in ${image_tags[@]}; do
					#download_scan_delete ${repository} ${img_tag}
					echo "Downloading: ${repository}:${img_tag}"
					docker pull ${repository}:${img_tag}
					echo "Scanning: ${repository}:${img_tag}"
					trivy image ${repository}:${img_tag} --format json --severity HIGH,CRITICAL --output ${ENG_HOME}/ecr/$(echo ${repository} | sed 's|/|_|g'):${img_tag}.trivy.json 2>&1 | tee -a ${ENG_HOME}/ecr/${account}.trivy.json
					echo echo "Removing: ${repository}:${img_tag}"
					docker rmi ${repository}:${img_tag}
				done
			else
				last_image_tag=$(aws --profile ${prof} --region ${region} ecr describe-images --repository-name ${repo} | jq -r '.imageDetails | sort_by(.imagePushedAt) | last | .imageTags[0]')
				if [[ "${last_image_tag}" != "null" ]]; then
					#download_scan_delete ${repository} ${late_image_tag}
					echo "Downloading: ${repository}:${last_image_tag}"
					docker pull ${repository}:${last_image_tag}
					echo "Scanning: ${repository}:${last_image_tag}"
					trivy image ${repository}:${last_image_tag} --format json --severity HIGH,CRITICAL --output ${ENG_HOME}/ecr/$(echo ${repository} | sed 's|/|_|g'):${last_image_tag}.trivy.json 2>&1 | tee -a ${ENG_HOME}/ecr/${account}.trivy.json
					echo "Removing: ${repository}:${last_image_tag}"
					docker rmi ${repository}:${last_image_tag}
				fi
			fi
		done
	done
n=$(( $n + 1 ))
done
