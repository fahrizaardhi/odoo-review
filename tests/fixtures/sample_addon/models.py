"""
Fixture: intentionally bad Odoo model code for testing checkers.
Contains: SQL injection, N+1, missing @api.depends, eval, hardcoded ID, sudo(True).
"""
from odoo import models, fields, api


class BadModel(models.Model):
    _name = 'bad.model'
    # Missing _description → OR023

    name = fields.Char()
    partner_id = fields.Many2one('res.partner')
    value = fields.Float(compute='_compute_value')  # no @api.depends → OR025

    def _compute_value(self):
        # Missing @api.depends
        for rec in self:
            rec.value = 0

    def action_do_stuff(self):
        partner_name = self.env.context.get('partner_name', '')

        # OR001: f-string in cr.execute  (intentionally insecure test fixture)
        self.env.cr.execute(f"SELECT id FROM res_partner WHERE name = '{partner_name}'")  # nosec B608

        # OR002: % formatting in cr.execute  (intentionally insecure test fixture)
        self.env.cr.execute("SELECT id FROM res_partner WHERE name = '%s'" % partner_name)  # nosec B608

        # OR010: search inside loop
        for rec in self:
            partner = self.env['res.partner'].search([('name', '=', rec.name)], limit=1)

        # OR011: write inside loop
        records = self.env['bad.model'].search([])
        for rec in records:
            rec.write({'value': 1.0})

        # OR022: hardcoded ID in browse
        admin = self.env['res.users'].browse(1)

        # OR026: eval usage  (intentionally insecure test fixture)
        result = eval("1 + 1")  # nosec B307

        # OR020: sudo(True)
        self.sudo(True).search([])

    def action_bad_sudo(self):
        # Blanket sudo without reason
        return self.sudo(True).search([('name', '=', 'test')])

    def action_bare_sudo(self):
        # OR021: bare sudo() — privilege escalation, should be confirmed
        return self.sudo().search([('name', '=', 'test')])
