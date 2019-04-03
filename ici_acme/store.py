        # TODO: make new file mode 0o600

    def purge_order(self, order_id):
        """ Remove an order and all it's resources. """
        order = self.load_order(order_id)
        for authz_id in order.authorization_ids:
            authz = self.load_authorization(authz_id)
            for chall_id in authz.challenge_ids:
                self.delete('challenge', chall_id)
            self.delete('authorization', authz_id)
        if order.certificate_id:
            self.delete('certificate', order.certificate_id)
        self.delete('order', order_id)