# linkSHARK

Issue linking for SmartSHARK. 

## Install

### via PIP
```bash
pip install https://github.com/smartshark/linkSHARK/zipball/master
```

### via setup.py
```bash
python setup.py install
```

## Execution for smartSHARK

The linkSHARK needs only access to the MongoDB and the name of the project for which commits should be linked. 
It requires that vcsSHARK and issueSHARK have already been run.

```bash
# this simply matches all commits to issues using regular expressions
python main.py -U $DBUSER -P $DBPASS -DB $DBNAME -u $REPOSITORY_GIT_URI -a $AUTHENTICATION_DB -n $PROJECT_NAME

# we can also correct broken issue links for JIRA using a list of broken names and the correct name
python main.py -U $DBUSER -P $DBPASS -DB $DBNAME -u $REPOSITORY_GIT_URI -a $AUTHENTICATION_DB -n $PROJECT_NAME --broken-keys PROJEKT --correct-key PROJECT
```
