'use strict';

const iptabler = require('iptabler');

function IptablerSmart() {
    this.allRules = [];
    this.allNatRules = [];
}

function asyncRunCommand(cmd) {
    return new Promise(function(resolve, reject) {
        cmd.exec(function(err, stdout) {
            if (err) {
                return reject(err);
            }
            return resolve(stdout);
        });
    });
}

IptablerSmart.prototype.getAllRules = async function() {
    let firewall = this;
    // First get a list of all existing rules
    const allRulesCmd = iptabler({
        sudo: true,
        S: ''
    });
    const allNatRulesCmd = iptabler({
        sudo: true,
        table: 'nat',
        S: ''
    });
    allRulesCmd._args.pop();
    allNatRulesCmd._args.pop();
    const promises = [];
    let ruleStr = await asyncRunCommand(allRulesCmd);
    let natRuleStr = await asyncRunCommand(allNatRulesCmd);

    firewall.allRules = ruleStr.split('\n');
    firewall.allNatRules = natRuleStr.split('\n');
};

IptablerSmart.prototype.applyRuleSafely = async function(rule, updateCurrent=true) {
    if (updateCurrent) {
        await this.getAllRules();
    }

    const iptablesRule = iptabler(rule);
    let cmd = iptablesRule._args.slice();
    cmd.shift();
    let ruleStr = cmd.join(' ');

    let ruleExists;
    if (ruleStr.indexOf('-t nat') >= 0) {
        // This is a nat rule
        ruleStr = ruleStr.replace('-t nat', '').trim();
        ruleExists = this.allNatRules.indexOf(ruleStr) >= 0;
    } else {
        ruleExists = this.allRules.indexOf(ruleStr) >= 0;
    }

    // Apply rule only if it doesn't already exist
    if (!ruleExists) {
        await this.applyRule(rule);
    }
};

IptablerSmart.prototype.applyRulesSafely = async function(rules) {
    await this.getAllRules();
    for (let i = 0; i < rules.length; i++) {
        await this.applyRuleSafely(rules[i], false);
    }
};

// This one is unsafe
IptablerSmart.prototype.applyRule = async function(rule) {
    await iptabler(rule).exec(function(stdout, err) {
        if(err) {
            throw err;
        }
    });
}

IptablerSmart.prototype.applyRules = async function(rules) {
    for (let i = 0; i < rules.length; i++) {
        await this.applyRule(rules[i]);
    }
}

module.exports = IptablerSmart;