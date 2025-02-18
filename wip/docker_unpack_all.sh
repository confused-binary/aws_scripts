images=($(docker images | awk '{print $1":"$2}' | grep -v "REPOSITORY:TAG"))
index=0
rm ./gitleaks_scan_me
while [[ "${index}" -lt "${#images[@]}" ]]; do
	if [[ "$(wc -l ./gitleaks_scan_me | cut -d' ' -f1)" -ge 5 ]]; then
		echo -ne "\rwaiting gitleaks to process some more"
		sleep 5
	else
		img=${images[${index}]}
		unpack_dir=$(echo ${img} | sed 's/:/_/g' | sed 's|/|_|g')
		if [[ ! -d "${unpack_dir}" ]]; then 
			# unpack directory
			mkdir ${unpack_dir}
			# delete previous
			docker stop temp-unpack
			docker rm -f temp-unpack
			# run container
			docker run -d --name temp-unpack ${img} top
			echo -e "\nrun: ${img}"
			# get workdir
			workdir=$(docker image inspect ${img} | jq -r '.[].Config.WorkingDir')
			# copy files
			docker cp temp-unpack:${workdir}/ ./${unpack_dir}/
			echo "cp: ${img}"
			# save to file
			echo "${unpack_dir}" >> ./gitleaks_scan_me
			echo "append: ${img}"
		fi
		index=$(( ${index} + 1 ))
	fi
done
