# get all ecr images
regions=(
  "us-east-1"
  "us-east-2"
  "us-west-1"
  "us-west-2"
  "eu-west-1"
  "eu-west-2"
  "eu-west-2"
)

for prof in $(aws configure list-profiles | grep "${ENG}"); do
	account=$(aws --profile ${prof} sts get-caller-identity | jq -r '.Account')
	for region in ${regions[@]}; do
		echo "Region: ${region}"
		aws --profile ${prof} ecr get-login-password --region ${region} | docker login --username AWS --password-stdin ${account}.dkr.ecr.${region}.amazonaws.com
		repositories=$(aws --profile ${prof} --region ${region} ecr describe-repositories | jq -r '.repositories[].repositoryName' | sort -u)
		for repo in ${repositories[@]}; do
			if [[ ${1} == "--all" ]]; then
				image_tags=($(aws --profile ${prof} --region ${region} ecr describe-images --repository-name ${repo} | jq -r --arg account "${account}" --arg region "${region}" '.imageDetails | sort_by(.imagePushedAt) | reverse | .[] | "\($account).dkr.ecr.\($region).amazonaws.com/\(.repositoryName):\(.imageTags[0])"'))
				for img_tag in ${image_tags[@]}; do
					echo "Downloading: ${img_tag}"
					docker pull ${img_tag}
				done
			else
				last_image_tag=$(aws --profile ${prof} --region ${region} ecr describe-images --repository-name ${repo} | jq -r '.imageDetails | sort_by(.imagePushedAt) | last | .imageTags[0]')
				if [[ "${last_image_tag}" != "null" ]]; then
					echo "Downloading: ${repo}:${last_image_tag}"
					docker pull ${account}.dkr.ecr.${region}.amazonaws.com/${repo}:${last_image_tag}
				fi
			fi
		done
	done
done
