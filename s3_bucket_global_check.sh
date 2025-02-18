# pass in profile name
if [[ $# -eq 0 ]]; then 
    echo "Error: Pass profile name or regex var to find name in `aws configure list-profiles`"
    exit
fi
PROF=$1

function bucket_check () {
    #https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-bucket-intro.html
    for bucket in $(aws --profile ${PROF} s3 ls | awk '{print $3}'); do
	    found=0
	    # Get bucket region since that's a thing for urls
        bucket_region=$(aws --profile ${PROF} s3api get-bucket-location --bucket ${bucket} | jq -r '.LocationConstraint')

        # Check with other profile
        cmd="aws --profile rt s3 ls ${bucket}"
        eval ${cmd} &>/dev/null && echo ${cmd} && found=1

        # Check Virtual-host style
        path="https://${bucket}.s3.${bucket_region}.amazonaws.com/"
        curl -k -s ${path} | grep -oPm1 "(?<=<Key>)[^<]+" 1>/dev/null && echo "${path}" && found=1

        # Check Path style
        path="https://s3.${bucket_region}.amazonaws.com/${bucket}/"
        curl -k -s ${path} | grep -oPm1 "(?<=<Key>)[^<]+" 1>/dev/null && echo "${path}" && found=1

	[[ "${found}" == 0 ]] && echo "${bucket},passed checks"
    done
}

if [[ "${PROF}" =~ "\[" ]]; then
    for PROF in $(grep "${1}" ~/.aws/credentials | tr -d "[]"); do
        bucket_check
    done
else
    bucket_check
fi

