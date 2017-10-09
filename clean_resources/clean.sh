#!/bin/bash

curl -s https://raw.githubusercontent.com/linuxautomations/scripts/master/common-functions.sh >/tmp/common-functions.sh
source /tmp/common-functions.sh

### Check AWS CLI Installed or not.
pip list 2>/dev/null| grep -w awscli &>/dev/null
if [ $? -ne 0 ]; then 
	error "AWSCLI not installed"
	hint "Run the following URL to setup AWSCLI"
	hint ""
	exit 1
fi

### Checking AWS Credentials.
if [ -z "$ACCESS_ID" -o -z "$ACCESS_KEY" ]; then 
	error "AWS Credentials are not set".
	info "Setup the AWS Access Keys as follows and then run the script"
	hint "export ACCESS_ID=<YOUR ACCESS ID> ; export ACCESS_KEY=<YOUR ACCESS KEY>"
	exit 1
fi

export AWS_ACCESS_KEY_ID=$ACCESS_ID ; export AWS_SECRET_ACCESS_KEY=$ACCESS_KEY
### Setting up AWS CLI 
REGIONS=(us-east-2 us-east-1 us-west-1 us-west-2 ca-central-1 ap-south-1 ap-northeast-2 ap-southeast-1 ap-southeast-2 ap-northeast-1 eu-central-1 eu-west-1 eu-west-2 sa-east-1)
SERVICES=(EC2 S3 ELASTIC_BEANSTALK RDS CODECOMMIT CODEBUILD CODEDEPLOY CODE_PIPELINE CLOUDWATCH SNS)

Check_EC2() {
	count=$(aws ec2 describe-instances --region $1 --output table | grep InstanceId | wc -l)
	count1=$(aws ec2 describe-volumes --region $1 --output table  | grep us-east-2 | wc -l)
	echo "$1,$count+$count1" >>$FILE
}

Check_S3() {
	count=$(aws s3 ls | wc -l)
	info "\t\t Number of S3 Buckets = $count"
}

Check_EB() {
	count=$(aws elasticbeanstalk  describe-applications  --region $1 | grep ApplicationName | wc -l)
	echo "$1,$count" >>$FILE
	#info "\t\t Number of Elastic Beanstalk Application = $count"
}

Check_RDS() {
	count=$(aws rds describe-db-instances --region $1 | grep DbiResourceId | wc -l)
	echo "$1,$count" >>$FILE
	#info "\t\t Number of Elastic Beanstalk Application = $count"
}

Check_CC() {
	count=$(aws codecommit list-repositories  --region $1 --output table | grep repositoryName | wc -l)
	echo "$1,$count" >>$FILE
}

Check_CB() {
	count=$(aws codebuild list-projects --region $1 --output text 2>/dev/null| wc -l)
	echo "$1,$count" >>$FILE
}

Check_CD() {
	count=$(aws deploy list-applications --region $1 --output text | wc -l )
	echo "$1,$count" >>$FILE
}

Check_CP() {
	count=$(aws codepipeline list-pipelines --region $1 --output text | wc -l )
	echo "$1,$count" >>$FILE
}

Check_CW() {
	count=$(aws cloudwatch describe-alarms --region $1 --output table | grep AlarmArn | wc -l )
	echo "$1,$count" >>$FILE
}

Check_SNS() {
	count=$(aws sns list-topics  --region $1 --output text |  wc -l )
	echo "$1,$count" >>$FILE
}

REPORT() {
	head_bu "AWS Resources List:"
	for SERVICE in ${SERVICES[*]} ; do 
		FILE=/tmp/$SERVICE
		rm -f $FILE
		head_u "\nChecking $R$SERVICE$N :"
		case $SERVICE in
			EC2)
			echo "  EC2 + EBS "
			for REGION in ${REGIONS[*]}; do
				Check_EC2 "$REGION"
			done
			echo -e "$(cat $FILE | awk -F , '{print $1}'|xargs|sed -e 's/ /,/g')\n$(cat $FILE | awk -F , '{print $2}'|xargs|sed -e 's/ /,/g')" | csvlook --no-inference
			;;
			S3)
				Check_S3 
			;;
			ELASTIC_BEANSTALK) 
			for REGION in ${REGIONS[*]}; do 
				Check_EB "$REGION"
			done
			echo -e "$(cat $FILE | awk -F , '{print $1}'|xargs|sed -e 's/ /,/g')\n$(cat $FILE | awk -F , '{print $2}'|xargs|sed -e 's/ /,/g')" | csvlook --no-inference
			;;
			RDS)
			for REGION in ${REGIONS[*]}; do 
				Check_RDS "$REGION"
			done
			echo -e "$(cat $FILE | awk -F , '{print $1}'|xargs|sed -e 's/ /,/g')\n$(cat $FILE | awk -F , '{print $2}'|xargs|sed -e 's/ /,/g')" | csvlook --no-inference
			;;
			CODECOMMIT)
			for REGION in ${REGIONS[*]}; do 
				Check_CC "$REGION"
			done
			echo -e "$(cat $FILE | awk -F , '{print $1}'|xargs|sed -e 's/ /,/g')\n$(cat $FILE | awk -F , '{print $2}'|xargs|sed -e 's/ /,/g')" | csvlook --no-inference
			;;
			CODEBUILD)
			for REGION in ${REGIONS[*]}; do 
				Check_CB "$REGION"
			done
			echo -e "$(cat $FILE | awk -F , '{print $1}'|xargs|sed -e 's/ /,/g')\n$(cat $FILE | awk -F , '{print $2}'|xargs|sed -e 's/ /,/g')" | csvlook --no-inference
			;;
			CODEDEPLOY)
			for REGION in ${REGIONS[*]}; do 
				Check_CD "$REGION"
			done
			echo -e "$(cat $FILE | awk -F , '{print $1}'|xargs|sed -e 's/ /,/g')\n$(cat $FILE | awk -F , '{print $2}'|xargs|sed -e 's/ /,/g')" | csvlook --no-inference
			;;
			CODE_PIPELINE) 
			for REGION in ${REGIONS[*]}; do 
				Check_CP "$REGION"
			done
			echo -e "$(cat $FILE | awk -F , '{print $1}'|xargs|sed -e 's/ /,/g')\n$(cat $FILE | awk -F , '{print $2}'|xargs|sed -e 's/ /,/g')" | csvlook --no-inference
			;;
			CLOUDWATCH)
			for REGION in ${REGIONS[*]}; do 
				Check_CW "$REGION"
			done
			echo -e "$(cat $FILE | awk -F , '{print $1}'|xargs|sed -e 's/ /,/g')\n$(cat $FILE | awk -F , '{print $2}'|xargs|sed -e 's/ /,/g')" | csvlook --no-inference
			;;
			SNS)
			for REGION in ${REGIONS[*]}; do 
				Check_SNS "$REGION"
			done
			echo -e "$(cat $FILE | awk -F , '{print $1}'|xargs|sed -e 's/ /,/g')\n$(cat $FILE | awk -F , '{print $2}'|xargs|sed -e 's/ /,/g')" | csvlook --no-inference
			;;
			*) break ;;
		esac
	done

}

case $1 in 
	report) REPORT ;;
	remove|clean) REMOVE ;;
	*) REPORT ;;
esac