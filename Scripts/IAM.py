import boto3
import json
import networkx as nx
from urllib.parse import unquote 

iam = boto3.client('iam') 

graph = nx.DiGraph()




print(f'{dir(iam)}')

