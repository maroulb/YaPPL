"""Module to create, parse and evaluate YaPPL-Policies.

.. moduleauthor: Max-R. Ulbricht (@maroulb)

"""

import json
import jsonschema
import datetime
import copy


def validate(policy):
    """Validate a passed YaPPL-Policy against the Standard YaPPL-Schema.

    arguments:
    policy -- the YaPPL-Policy to validate
    """
    try:
        yappl_schema = open('YaPPL_schema.json', 'r')
        yappl_load = True
    except IOError:
        yappl_load = False

    if yappl_load:
        yappl_schema = yappl_schema.read()
        yappl_schema = json.loads(yappl_schema)
        policy = json.loads(policy)
    else:
        return 'SchemaLoadError'

    try:
        val_result = jsonschema.validate(policy, yappl_schema)
        return 'valid'
    except jsonschema.SchemaError:
        return 'SchemaError'
    except jsonschema.ValidationError:
        return 'ValidationError'  # TODO: more precise error description
        """
        val_result = jsonschema.validate(policy, yappl_schema)
        errors = sorted(val_result.iter_errors(policy), key=lambda e: e.path)
        for error in errors:
            for suberror in sorted(error.context, key=lambda e: e.schema_path):
                eList = list((suberror.schema_path), suberror.message, sep=", ")
        return json.loads(eList)
        """
    except:
        return 'an error occurred'

    val_result = val_result  # ???


def parse(json_policy):
    """Parse a YaPPL-Policy in JSON format into a python object.

    arguments:
    json_policy -- the policy to parse
    """
    json_policy = json.loads(json_policy)
    print 'parse...'
    policy = YaPPL()

    policy.setId(json_policy['_id'])

    policy.Preference = []

    for i in range(len(json_policy['preference'])):
        rule = {}
        rule['Id'] = i

        purpose = {}
        purpose['permitted'] = []
        purpose['excluded'] = []

        utilizer = {}
        utilizer['permitted'] = []
        utilizer['excluded'] = []

        transformation = []

        for j in range(len(json_policy['preference'][i]['rule']['purpose']['permitted'])):
            purpose['permitted'].append(str(json_policy['preference'][i]['rule']['purpose']['permitted'][j]).encode('utf-8'))

        for j in range(len(json_policy['preference'][i]['rule']['purpose']['excluded'])):
            purpose['excluded'].append(str(json_policy['preference'][i]['rule']['purpose']['excluded'][j]).encode('utf-8'))

        for j in range(len(json_policy['preference'][i]['rule']['utilizer']['permitted'])):
            utilizer['permitted'].append(str(json_policy['preference'][i]['rule']['utilizer']['permitted'][j]).encode('utf-8'))

        for j in range(len(json_policy['preference'][i]['rule']['utilizer']['excluded'])):
            utilizer['excluded'].append(str(json_policy['preference'][i]['rule']['utilizer']['excluded'][j]).encode('utf-8'))

        for j in range(len(json_policy['preference'][i]['rule']['transformation'])):
            tr = {}
            tr['attribute'] = str(json_policy['preference'][i]['rule']['transformation'][j]['attribute'])
            tr['tr_func'] = str(json_policy['preference'][i]['rule']['transformation'][j]['tr_func'])
            transformation.append(tr)

        valid_from = str(json_policy['preference'][i]['rule']['valid_from']).encode('utf-8')

        exp_date = str(json_policy['preference'][i]['rule']['exp_date']).encode('utf-8')

        rule['Purpose'] = purpose
        rule['Utilizer'] = utilizer
        rule['Transformation'] = transformation
        rule['Valid_From'] = valid_from
        rule['Exp_Date'] = exp_date

        if i == 0:
            policy.setRuleId(i, i)
            for j in range(len(purpose['permitted'])):
                policy.setPermittedPurpose(i, purpose['permitted'][j])
            for j in range(len(purpose['excluded'])):
                policy.setExcludedPurpose(i, purpose['excluded'][j])
            for j in range(len(utilizer['permitted'])):
                policy.setPermittedUtilizer(i, utilizer['permitted'][j])
            for j in range(len(utilizer['excluded'])):
                policy.setExcludedUtilizer(i, utilizer['excluded'][j])
            for j in range(len(transformation)):
                policy.setTransformation(i, transformation[j])
            policy.setValid_From(i, valid_from)
            policy.setExp_Date(i, exp_date)
        else:
            policy.addRule(rule)

    return policy


class YaPPL:

    def __init__(self):

        self.__Id = '0000'

        self.__Preference = []

        self.__Rule = {}

        self.__Rule['Id'] = ''

        self.__Rule['Purpose'] = {}
        self.__Rule['Purpose']['permitted'] = []
        self.__Rule['Purpose']['excluded'] = []

        self.__Rule['Utilizer'] = {}
        self.__Rule['Utilizer']['permitted'] = []
        self.__Rule['Utilizer']['excluded'] = []

        self.__Rule['Transformation'] = []

        self.__Rule['Valid_From'] = '0000-00-00T00:00:00.00Z'
        self.__Rule['Exp_Date'] = '0000-00-00T00:00:00.00Z'

        self.__Preference.append(self.__Rule)

#  <public_methods> (Policy Creation, CRUD Rules & getExcludedEntities)

    def createPolicy(self):
        """Create a YaPPL compliant Policy in JSON format from the respective python object.

        arguments:
        none
        """
        json_policy = {}
        json_policy['_id'] = self.__Id
        json_policy['preference'] = []

        for i in range(len(self.__Preference)):
            rule = {}
            rule['purpose'] = self.__Preference[i]['Purpose']
            rule['utilizer'] = self.__Preference[i]['Utilizer']
            rule['transformation'] = self.__Preference[i]['Transformation']
            rule['valid_from'] = self.__Preference[i]['Valid_From']
            rule['exp_date'] = self.__Preference[i]['Exp_Date']
            newRule = {}
            newRule['rule'] = rule
            json_policy['preference'].append(newRule)

        json_policy = json.dumps(json_policy, indent=2)
        return json_policy

    def getExcludedPurpose(self):
        """Return ALL excluded Purposes.

        arguments:
        none

        If a requested processing purpose is in this list, all data transfer should be prohibited
        """
        purpose = self.getPurpose()
        excludedPurpose = purpose['excluded']
        return excludedPurpose

    def getExcludedUtilizer(self):
        """Return ALL excluded Utilizers.

        arguments:
        none

        If the requesting institution is in this list, all data transfer should be prohibited
        """
        utilizer = self.getUtilizer()
        excludedUtilizer = utilizer['excluded']
        return excludedUtilizer

#  --- CRUD Rules ---  #

    def newRule(self, permittedPurpose, excludedPurpose, permittedUtilizer, excludedUtilizer, transformation):
        """Append a new Rule to a Preference.

        arguments:
        permittedPurpose -- [list] of permitted purposes
        excludedPurpose -- [list] of excluded purposes
        permittedUtilizer -- [list] of permitted utilizers
        excludedUtilizer -- [list] of excluded utilizers
        transformation -- [list] of transformation objects
        """
        rule = {}
        rule['Id'] = len(self.__Preference)
        rule['Purpose'] = {}
        rule['Purpose']['permitted'] = permittedPurpose
        rule['Purpose']['excluded'] = excludedPurpose
        rule['Utilizer'] = {}
        rule['Utilizer']['permitted'] = permittedUtilizer
        rule['Utilizer']['excluded'] = excludedUtilizer
        rule['Transformation'] = transformation
        rule['Valid_From'] = datetime.datetime.now().isoformat('T')[:-4] + 'Z'  # RFC 3339 compliant format needed for validation
        rule['Exp_Date'] = '0000-00-00T00:00:00.00Z'
        self.addRule(rule)

    def getTrRules(self):
        """Return all Transformation Rules.

        arguments:
        none

        This method enables the execution of data transformations according to the rules in a policy. A desired transformation depends on given combinations of Purposes and Utilizers.
        e.g.:
        If the requesting institution is in the returned ['Utilizer'] list AND the requested processing purpose is in the ['Purpose'] list, the functions inside the ['Transformation'] list have to be performed before data transfer.
        """
        trRules = []
        for i in range(len(self.__Preference)):
            if self.__Preference[i]['Exp_Date'] == '0000-00-00T00:00:00.00Z':
                rule = {}
                rule['Purpose'] = self.__Preference[i]['Purpose']['permitted']
                rule['Utilizer'] = self.__Preference[i]['Utilizer']['permitted']
                rule['Transformation'] = self.__Preference[i]['Transformation']
                trRules.append(rule)
            else:
                pass
        return trRules

    def archiveRule(self, ruleID):
        """Archive a Rule for potential audits.

        arguments:
        ruleID -- the ID of the rule to be archived
        """
        self.setExp_Date(ruleID, datetime.datetime.now().isoformat('T')[:-4] + 'Z')
        self.setRuleId(ruleID, -1)

    def updateRule(self, ruleID, permittedPurpose=[], excludedPurpose=[], permittedUtilizer=[], excludedUtilizer=[], transformation=[]):
        """Update a Rule with new Values.

        arguments:
        ruleID -- ID of the rule to be updated
        permittedPurpose -- [list] of permitted purposes
        excludedPurpose -- [list] of excluded purposes
        permittedUtilizer -- [list] of permitted utilizers
        excludedUtilizer -- [list] of excluded utilizers
        transformation -- [list] of transformation objects

        at least the ID and ONE updated Value should be present
        """
        # TODO: avoid updating an attribute with an already existing value
        #  aka 1. newRule with old + updated attribute values
        #      2. delete old Rule (aka set Exp_date and archive)
#        oldRule = dict(self.getRule(ruleID))
        oldRule = copy.deepcopy(self.getRule(ruleID))
        if len(permittedPurpose) > 0:
            for i in range(len(permittedPurpose)):
                oldRule['Purpose']['permitted'].append(permittedPurpose[i])
        if len(excludedPurpose) > 0:
            for i in range(len(excludedPurpose)):
                oldRule['Purpose']['excluded'].append(excludedPurpose[i])
        if len(permittedUtilizer) > 0:
            for i in range(len(permittedUtilizer)):
                oldRule['Utilizer']['permitted'].append(permittedUtilizer[i])
        if len(excludedUtilizer) > 0:
            for i in range(len(excludedUtilizer)):
                oldRule['Utilizer']['excluded'].append(excludedUtilizer[i])
        if len(transformation) > 0:
            for i in range(len(transformation)):
                oldRule['Transformation'].append(transformation[i])

        self.newRule(oldRule['Purpose']['permitted'], oldRule['Purpose']['excluded'], oldRule['Utilizer']['permitted'], oldRule['Utilizer']['excluded'], oldRule['Transformation'])

        self.archiveRule(self.getRule(ruleID)['Id'])

#  </public_methods>

#  ###### private methods ######  #
#  TODO: make them real private aka "__method()" without breaking parse()  #
    def isRuleUnique(self, rule):
        for i in range(len(self.__Preference)):
            if self.__Preference[i]['Purpose'] == rule['Purpose']:
                if self.__Preference[i]['Utilizer'] == rule['Utilizer']:
                    if self.__Preference[i]['Transformation'] == rule['Transformation']:
                        if self.__Preference[i]['Exp_Date'] == rule['Exp_Date']:
                            return False
        return True

    def addRule(self, rule):
        if self.isRuleUnique(rule):
            self.__Preference.append(rule)
        else:
            return

    def __str__(self):
        locPref = []
        locId = str(self.__Id)
        for i in range(len(self.__Preference)):
            Rule = {}
            Rule['Id'] = str(self.__Preference[i]['Id'])
            Rule['Purpose'] = str(self.__Preference[i]['Purpose'])
            Rule['Utilizer'] = str(self.__Preference[i]['Utilizer'])
            Rule['Transformation'] = str(self.__Preference[i]['Transformation'])
            Rule['Exp_Date'] = str(self.__Preference[i]['Exp_Date'])
            locPref.append(Rule)
        return 'Id: ' + locId + '\n\nPreference: \n\n' + str(locPref)

    def getId(self):
        return self.__Id

    def getPreference(self):
        return self.__Preference

    def getRule(self, ruleID):
        return self.__Preference[ruleID]

    def getPurpose(self):
        purpose = {}
        purpose['permitted'] = []
        purpose['excluded'] = []
        for i in range(len(self.__Preference)):
            for j in range(len(self.__Preference[i]['Purpose']['permitted'])):
                if self.__Preference[i]['Purpose']['permitted'][j] not in purpose['permitted']:
                    purpose['permitted'].append(str(self.__Preference[i]['Purpose']['permitted'][j]))
            for j in range(len(self.__Preference[i]['Purpose']['excluded'])):
                if self.__Preference[i]['Purpose']['excluded'][j] not in purpose['excluded']:
                    purpose['excluded'].append(str(self.__Preference[i]['Purpose']['excluded'][j]))
        return purpose

    def getPermittedPurpose(self):
        purpose = self.getPurpose()
        permittedPurpose = purpose['permitted']
        return permittedPurpose

    def getUtilizer(self):
        utilizer = {}
        utilizer['permitted'] = []
        utilizer['excluded'] = []
        for i in range(len(self.__Preference)):
            for j in range(len(self.__Preference[i]['Utilizer']['permitted'])):
                if self.__Preference[i]['Utilizer']['permitted'][j] not in utilizer['permitted']:
                    utilizer['permitted'].append(str(self.__Preference[i]['Utilizer']['permitted'][j]))
            for j in range(len(self.__Preference[i]['Utilizer']['excluded'])):
                if self.__Preference[i]['Utilizer']['excluded'][j] not in utilizer['excluded']:
                    utilizer['excluded'].append(str(self.__Preference[i]['Utilizer']['excluded'][j]))
        return utilizer

    def getPermittedUtilizer(self):
        utilizer = self.getUtilizer()
        permittedUtilizer = utilizer['permitted']
        return permittedUtilizer

    def getTransformation(self):
        transformations = []
        for i in range(len(self.__Preference)):
            transformations.append(self.__Preference[i]['Transformation'])
        return transformations

    def getExp_Date(self):
        exp_date = []
        for i in range(len(self.__Preference)):
            exp_date.append(self.__Preference[i]['Exp_Date'])
        return exp_date

    def setId(self, id):
        self.__Id = id

    def setRuleId(self, ruleId, newId):
        self.__Preference[ruleId]['Id'] = newId

    def setPermittedPurpose(self, ruleId, purpose):
        if purpose in self.__Preference[ruleId]['Purpose']['permitted']:
            pass
        else:
            self.__Preference[ruleId]['Purpose']['permitted'].append(purpose)

    def setExcludedPurpose(self, ruleId, purpose):
        if purpose in self.__Preference[ruleId]['Purpose']['excluded']:
            pass
        else:
            self.__Preference[ruleId]['Purpose']['excluded'].append(purpose)

    def setPermittedUtilizer(self, ruleId, utilizer):
        if utilizer in self.__Preference[ruleId]['Utilizer']['permitted']:
            pass
        else:
            self.__Preference[ruleId]['Utilizer']['permitted'].append(utilizer)

    def setExcludedUtilizer(self, ruleId, utilizer):
        if utilizer in self.__Preference[ruleId]['Utilizer']['excluded']:
            pass
        else:
            self.__Preference[ruleId]['Utilizer']['excluded'].append(utilizer)

    def setTransformation(self, ruleId, transformation):
        """
        Method to set Transformation.

        takes a 'transformation'-object in the form of {"attribute": "type:string", "tr_func": "type:string"} and append it to a YaPPL-instance if not still present
        """
        if transformation in self.__Preference[ruleId]['Transformation']:
            pass
        else:
            self.__Preference[ruleId]['Transformation'].append(transformation)

    def setValid_From(self, ruleId, valid_from):
        self.__Preference[ruleId]['Valid_From'] = valid_from

    def setExp_Date(self, ruleId, exp_date):
        self.__Preference[ruleId]['Exp_Date'] = exp_date

    def main():
        pass

    if __name__ == '__main__':
        main()
