# iptabler-smart
A wrapper for the iptabler module with some useful functionality.

The main thing this module offers is the ability to only apply rules that aren't already applied. Currently iptabler will raise a signal and cause your program to terminate if you apply a rule that already exists. This module's applyRuleSafely() method will check against existing firewall rules and only create the rule if it doesn't already exist.

## Usage
```
const fw = new iptabler();

const createMyChain = {
    sudo: true,
    table: 'nat',
    new_chain: 'MYCHAIN'
};


fw.applyRuleSafely(createMyChain).then(() => {

    // Apply the rule safely, fetching existing rules first
    return fw.applyRuleSafely(createMyChain);

}).then(() => {

    // Applying the same rule again. This time it won't be applied since it is already present.
    return fw.applyRuleSafely(createMyChain);

}).then(() => {

    // Apply the rule safely, without first fetching existing rules
    return fw.applyRuleSafely({
        sudo: true,
        table: 'nat',
        new_chain: 'MYCHAIN2'
    }, false);

}).then(() => {

    let newChainRules = [
        {
            sudo: true,
            table: 'nat',
            append: 'POSTROUTING',
            jump: 'MYCHAIN'
        },
        {
            sudo: true,
            table: 'nat',
            append: 'MYCHAIN',
            out_interface: 'cni0',
            jump: 'MASQUERADE'
        }
    ];

    /*
     * Apply the array of rules. Fetches existing rules at the beginning,
     * and then applies the rules after.
     */
    return fw.applyRulesSafely(newChainRules);

}).then(() => {

    // Fetch all the rules manually so they will be up-to-date for next time
    return fw.getAllRules();

}).then(() => {
    console.log('done');
});
```

## Methods
|Method name|Parameters|Function|
|-----------|----------|--------|
|getAllRules|None|Fetches existing rules so we know what has been applied|
|applyRuleSafely|<ul><li>**_rule_** - iptabler rule </li><li> **_updateCurrent_** - call getAllRules before running this rule (default: true)</li></ul>|Apply rule only if it hasn't been applied already|
|applyRulesSafely|<ul><li>**_rules_** - array of iptabler rules</li></ul>|Calls applyRuleSafely for each rule in the array, only calling getAllRules at the beginning|
|applyRule|<ul><li>**_rule_** - iptabler rule</li></ul>|Simply execs iptabler rule without checking (unsafe)|
|applyRules|<ul><li>**_rules_** - array of iptabler rules</li></ul>|calls applyRule on all rules in the array (unsafe)|