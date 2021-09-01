'use strict';
const mockRequire = require('mock-require');
const realIptabler = require('iptabler');
let errors = [];
let outputs = [];
/*
 * Create mock iptabler object
 */

mockRequire('iptabler', function(options) {
    const real = realIptabler(options);
    return {
        _args: real._args,
        exec: function(fn) {
            const err = errors.shift();
            if (err) {
                return fn(err, null);
            }
            return fn(null, outputs.shift());
        }
    }
})

const IptablerSmart = require('../lib/iptablerSmart');
const iptabler = require('iptabler');
const sandbox = require('sinon').createSandbox();
const expect = require('chai').expect;

const getAllRulesResult = `
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-N ROUTER-FORWARD
-A FORWARD -j ROUTER-FORWARD
-A ROUTER-FORWARD -i eth0 -o eth1 -m state --state RELATED,ESTABLISHED -j ACCEPT
-A ROUTER-FORWARD -i eth1 -o eth0 -j ACCEPT
-A ROUTER-FORWARD -i eth0 -o wlan0 -m state --state RELATED,ESTABLISHED -j ACCEPT
-A ROUTER-FORWARD -i wlan0 -o eth0 -j ACCEPT
`;

const getAllRulesNatResult = `
-P PREROUTING ACCEPT
-P INPUT ACCEPT
-P POSTROUTING ACCEPT
-P OUTPUT ACCEPT
-N ROUTER-INGRESS
-N ROUTER-EGRESS
-A PREROUTING -j ROUTER-INGRESS
-A POSTROUTING -j ROUTER-EGRESS
-A ROUTER-INGRESS -s 192.168.5.1/32 -j RETURN
-A ROUTER-INGRESS -s 192.168.6.1/32 -j RETURN
-A ROUTER-EGRESS -o eth0 -j MASQUERADE
`;

describe('/lib/iptablerSmart', function() {
    describe('getAllRules', function() {
        beforeEach(function() {
            errors = []
            outputs = [];
        });

        it('valid', function(done) {
            outputs.push(getAllRulesResult);
            outputs.push(getAllRulesNatResult);
            const fw = new IptablerSmart();
            fw.getAllRules().then(() => {
                expect(JSON.stringify(fw.allRules)).eql(JSON.stringify(getAllRulesResult.split('\n')));
                expect(JSON.stringify(fw.allNatRules)).eql(JSON.stringify(getAllRulesNatResult.split('\n')));
                done();
            });
        });

        it('failed', function(done) {
            errors.push(new Error('iptables failure'));
            const fw = new IptablerSmart();
            fw.getAllRules().then(() => {
                done(new Error('should have thrown error'));
            }).catch(err => {
                done();
            });
        });
    }); // end getAllRules

    describe('applyRuleSafely', function() {
        beforeEach(function() {
            outputs.push(getAllRulesResult);
            outputs.push(getAllRulesNatResult);
        });

        it('new rule', function(done) {
            const fw = new IptablerSmart();
            fw.applyRuleSafely({
                sudo: true,
                table: 'nat',
                append: 'PREROUTING',
                jump: 'MYCHAIN'
            }).then(() => {
                done();
            })
        });

        it('existing rule', function(done) {
            const fw = new IptablerSmart();
            fw.applyRuleSafely({
                sudo: true,
                table: 'nat',
                append: 'ROUTER-INGRESS',
                source: '192.168.5.1/32',
                jump: 'RETURN'
            }).then(() => {
                done();
            })
        });

        it('with replacements', function(done) {
            const fw = new IptablerSmart();
            fw.applyRuleSafely({
                "sudo": true,
                "append": "ROUTER-FORWARD",
                "in_interface": "WAN",
                "out_interface": "LAN",
                "match": "state",
                "state": "RELATED,ESTABLISHED",
                "jump": "ACCEPT"
            }, true, {
                'WAN': 'eth0',
                'LAN': 'eth1'
            }).then(() => {
                done();
            })
        });
    }); // end applyRuleSafely

    describe('applyRulesSafely', function() {
        beforeEach(function() {
            outputs.push(getAllRulesResult);
            outputs.push(getAllRulesNatResult);
        });

        it('new rule', function(done) {
            const fw = new IptablerSmart();
            fw.applyRulesSafely([{
                sudo: true,
                table: 'nat',
                append: 'PREROUTING',
                jump: 'MYCHAIN'
            }]).then(() => {
                done();
            })
        });

        it('existing rule', function(done) {
            const fw = new IptablerSmart();
            fw.applyRulesSafely([{
                sudo: true,
                table: 'nat',
                append: 'ROUTER-INGRESS',
                source: '192.168.5.1/32',
                jump: 'RETURN'
            }]).then(() => {
                done();
            })
        });

        it('with replacements', function(done) {
            const fw = new IptablerSmart();
            fw.applyRulesSafely([{
                "sudo": true,
                "table": "nat",
                "append": "ROUTER-INGRESS",
                "source": "GATEWAY_IP",
                "jump": "RETURN"
            },{
                "sudo": true,
                "append": "ROUTER-FORWARD",
                "in_interface": "WAN",
                "out_interface": "LAN",
                "match": "state",
                "state": "RELATED,ESTABLISHED",
                "jump": "ACCEPT"
            },{
                "sudo": true,
                "append": "ROUTER-FORWARD",
                "in_interface": "LAN",
                "out_interface": "WAN",
                "jump": "ACCEPT"
            }], {
                'WAN': 'eth0',
                'LAN': 'eth1',
                'GATEWAY_IP': '192.168.4.1'
            }).then(() => {
                done();
            })
        });
    }); // end applyRulesSafely

    describe('applyRule', function() {
        it('new rule', function(done) {
            const fw = new IptablerSmart();
            fw.applyRule({
                sudo: true,
                table: 'nat',
                append: 'PREROUTING',
                jump: 'MYCHAIN'
            }).then(() => {
                done();
            })
        });

        it('existing rule', function(done) {
            const fw = new IptablerSmart();
            fw.applyRule({
                sudo: true,
                table: 'nat',
                append: 'ROUTER-INGRESS',
                source: '192.168.5.1/32',
                jump: 'RETURN'
            }).then(() => {
                done();
            })
        });

        it('with replacements', function(done) {
            const fw = new IptablerSmart();
            fw.applyRule({
                "sudo": true,
                "append": "ROUTER-FORWARD",
                "in_interface": "WAN",
                "out_interface": "LAN",
                "match": "state",
                "state": "RELATED,ESTABLISHED",
                "jump": "ACCEPT"
            }, {
                'WAN': 'eth0',
                'LAN': 'eth1'
            }).then(() => {
                done();
            })
        });
    }); // end applyRule

    describe('applyRules', function() {

        it('new rule', function(done) {
            const fw = new IptablerSmart();
            fw.applyRules([{
                sudo: true,
                table: 'nat',
                append: 'PREROUTING',
                jump: 'MYCHAIN'
            }]).then(() => {
                done();
            })
        });

        it('existing rule', function(done) {
            const fw = new IptablerSmart();
            fw.applyRules([{
                sudo: true,
                table: 'nat',
                append: 'ROUTER-INGRESS',
                source: '192.168.5.1/32',
                jump: 'RETURN'
            }]).then(() => {
                done();
            })
        });

        it('with replacements', function(done) {
            const fw = new IptablerSmart();
            fw.applyRules([{
                "sudo": true,
                "table": "nat",
                "append": "ROUTER-INGRESS",
                "source": "GATEWAY_IP",
                "jump": "RETURN"
            },{
                "sudo": true,
                "append": "ROUTER-FORWARD",
                "in_interface": "WAN",
                "out_interface": "LAN",
                "match": "state",
                "state": "RELATED,ESTABLISHED",
                "jump": "ACCEPT"
            },{
                "sudo": true,
                "append": "ROUTER-FORWARD",
                "in_interface": "LAN",
                "out_interface": "WAN",
                "jump": "ACCEPT"
            }], {
                'WAN': 'eth0',
                'LAN': 'eth1',
                'GATEWAY_IP': '192.168.4.1'
            }).then(() => {
                done();
            })
        });
    }); // end applyRules
});