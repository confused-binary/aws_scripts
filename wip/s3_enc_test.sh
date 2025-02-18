prof="wc-c"
for bucket in $(aws --profile ${prof} s3 ls | awk '{print $3}'); do
  result=$(aws --profile ${prof} s3api get-bucket-encryption --bucket ${bucket} --query 'ServerSideEncryptionConfiguration.Rules[].ApplyServerSideEncryptionByDefault.SSEAlgorithm' --output=text 2> /dev/null)
  if [[ -z "${result}" ]]; then
    echo "${prof},${bucket},No Encryption"
  else
    echo "${prof},${bucket},${result}"
  fi
done

