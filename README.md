# IAM-User-Analyzer
This personal project was developed to further my learning and acquisition of skills in access control. I seek to gain hands on experience on how real access management systems work through the development of this small scale IAM user analyzer than provides security assessments on IAM users on the AWS server, by flagging security threats.

- The Analyzer will be web served on the web and run on the local browser and not involve actual AWS EC2 instances. However the analyzer will use real AWS IAM User instances for its analysis.

- The program will written in python utilizing the boto3 SDK specialized for AWS scripting.

- NetworkX will be used to render the graphs used in the analyzer interface to build a node/edge structure which will visualize every subject and system object along with actions.