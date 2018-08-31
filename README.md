# linkSHARK

Issue linking for SmartSHARK. 

## Install

### via PIP
```bash
pip install https://github.com/smartshark/linkSHARK/zipball/master --process-dependency-links
```
The --process-dependency-links switch is needed because we install pycoSHARK as a requirement directly from git.

### via setup.py
```bash
python setup.py install
```

## Run Tests
```bash
python setup.py test
```

## Execution for smartSHARK

linkSHARK needs only access to the MongoDB and the URL of the repository which commits should be labeled. It requires that vcsSHARK and issueSHARK have already been run.
```bash
# This uses all issue tracking systems registered and mined for the project.
# It also uses every labeling approach available.
python main.py -U $DBUSER -P $DBPASS -DB $DBNAME -u $REPOSITORY_GIT_URI -a $AUTHENTICATION_DB -n $PROJECT_NAME

# we can also limit issue tracking systems and labeling approaches
python main.py -U $DBUSER -P $DBPASS -DB $DBNAME -u $REPOSITORY_GIT_URI -a $AUTHENTICATION_DB -n $PROJECT_NAME
```
