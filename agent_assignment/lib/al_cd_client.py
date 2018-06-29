from CDAuth import CDAuth

class CloudDefender(CDAuth):
    def __init__(self, args):
        self.service = "tm"
        CDAuth.__init__(self,args)

    def get_appliance(self):
        self.service = "tm"
        return self.query(self.service, [self.account_id, "appliances"])

    def get_appliance_custom(self, query_args=None):
        self.service = "tm"
        return self.query(self.service, [self.account_id, "appliances"], query_args)

    def get_phost(self):
        self.service = "tm"
        return self.query(self.service, [self.account_id, "protectedhosts"])

    def get_phost_custom(self, query_args=None):
        self.service = "tm"
        return self.query(self.service, [self.account_id, "protectedhosts"], query_args)

    def get_policy(self, query_args=None):
        self.service = "tm"
        return self.query(self.service, [self.account_id, "policies"], query_args)

    def update_phost(self, phost_id, payload):
        self.service = "tm"
        return self.modify(self.service, [self.account_id, "protectedhosts", phost_id], version="v1", method="post", payload=payload, json_response=False)
