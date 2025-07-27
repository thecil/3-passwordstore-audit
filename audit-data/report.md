---
title: Protocol Audit Report
author: Carlos Zambrano
date: July 27, 2025
header-includes:
  - \usepackage{titling}
  - \usepackage{graphicx}
---

\begin{titlepage}
    \centering
    \begin{figure}[h]
        \centering
        \includegraphics[width=0.5\textwidth]{logo.pdf} 
    \end{figure}
    \vspace*{2cm}
    {\Huge\bfseries Protocol Audit Report\par}
    \vspace{1cm}
    {\Large Version 1.0\par}
    \vspace{2cm}
    {\Large\itshape Cyfrin.io\par}
    \vfill
    {\large \today\par}
\end{titlepage}

\maketitle

<!-- Your report starts here! -->

Prepared by: [thecil](https://github.com/thecil/)
Lead Auditors: 
- Carlos Zambrano (thecil)

# Table of Contents
- [Table of Contents](#table-of-contents)
- [Protocol Summary](#protocol-summary)
- [Disclaimer](#disclaimer)
- [Risk Classification](#risk-classification)
- [Audit Details](#audit-details)
  - [Scope](#scope)
  - [Roles](#roles)
- [Executive Summary](#executive-summary)
  - [Issues found](#issues-found)
- [Findings](#findings)
- [High](#high)
- [Medium](#medium)
- [Low](#low)
- [Informational](#informational)
- [Gas](#gas)

# Protocol Summary

PasswordStore is a protocol dedicated to storage and retrieval of a user's passwords. The protocol is designed to be used by a single user, and is not designed to be used by multiple users. Only the owner should be able to set and access this password.

# Disclaimer

The Carlos Zambrano team makes all effort to find as many vulnerabilities in the code in the given time period, but holds no responsibilities for the findings provided in this document. A security audit by the team is not an endorsement of the underlying business or product. The audit was time-boxed and the review of the code was solely on the security aspects of the Solidity implementation of the contracts.

# Risk Classification

|            |        | Impact |        |     |
| ---------- | ------ | ------ | ------ | --- |
|            |        | High   | Medium | Low |
|            | High   | H      | H/M    | M   |
| Likelihood | Medium | H/M    | M      | M/L |
|            | Low    | M      | M/L    | L   |

We use the [CodeHawks](https://docs.codehawks.com/hawks-auditors/how-to-evaluate-a-finding-severity) severity matrix to determine severity. See the documentation for more details.

# Audit Details 

**The findings described in this document correspond the following commit hash:**
```
2e8f81e263b3a9d18fab4fb5c46805ffc10a9990
```

## Scope 

```
./src/
#-- PasswordStore.sol
```

## Roles

- Owner: The user who can set the password and read the password.
- Outsides: No one else should be able to set or read the password.

# Executive Summary

*Add some notes about how the audit went, types of things you found, etc.*

*We spent X hours with Z auditors using Y tools. etc*

## Issues found

| Severity | Number of Issues found |
|--------- |------------------------|
| High     | 2                      |
| Medium   | 0                      |
| Low      | 0                      |
| Info     | 1                      |
| Total    | 3                      |

# Findings
# High

### [H-1] Private Variable `s_password` is visible to anyone anyone who has access to the blockchain to read the password stored in.

**Description**: The private variable `PasswordStore::s_password` can be read by anyone who has access to the blockchain.

**Impact**: This vulnerability allows attackers to see the password stored in.

**Proof of Concept**: (Proof of Code)

The below test case shows how anyone can read the password directly from the blockchain.

<details>
<summary>Code Instructions</summary>

1. Create a locally running chain
```bash
make anvil
```

2. Deploy the contract to the chain.
```bash
make deploy
```
3. Run the storage tool
Call the slot # 1 of the contract which is where the `PasswordStore::s_password` is stored.

```bash
cast storage <CONTRACT_ADDRESS_HERE> 1 --rpc-url http://localhost:8545
```
At first deploy, the output will be: `0x6d7950617373776f726400000000000000000000000000000000000000000014`

4. Parse the value to string
```bash
cast parse-bytes32-string <HEX_VALUE_HERE>
```
At first deploy, the output will be: `myPassword`

</details>

**Recommended Mitigation**: Due to this, the overall architecture of the contract should be rethought. One could encrypt the password off-chain, and then store the encrypted password on-chain. This would require the user to remember another password off-chain to decrypt the password. However, you'd also likely want to remove the view function as you wouldn't want the user to accidentally send a transaction with the password that decrypts yours password.

------

### [H-2] The `PasswordStore::setPassword` function is not Access Controlled for Only Owner, non-owner could change the password.

**Description**: The `PasswordStore::setPassword` function is set to be an `external` function, however, the natspec of the function and overall purpose of the smart contract is `This function allows only the owner to set a new password.`

```javascript
    /*
     * @notice This function allows only the owner to set a new password.
     * @param newPassword The new password to set.
     */
    //  @audit - no access control for only owner, everyone can set the password.
    function setPassword(string memory newPassword) external {
```

**Impact**: This vulnerability allows attackers to set a new password without authorization.

**Proof of Concept**: An attacker can call the `PasswordStore::setPassword` function and set a new password without authorization. Once the attacker sets a new password, they can use it to access other functions in the contract.

(Proof of Code)

The below test case shows how anyone can set a new password without being the contract owner.
Check `test/PasswordStore.t.sol` for more details.

<details>
<summary>Code unit test</summary>

```javascript
    function test_non_owner_can_set_password(address randomAddress) public {
        // ensure the owner is not the same as the random address
        vm.assume(owner != randomAddress);
        // start the prank with the random address
        vm.prank(randomAddress);
        string memory expectedPassword = "myNewPassword";
        // set the new password as the random address
        passwordStore.setPassword(expectedPassword);
        // start prank as the contract owner
        vm.prank(owner);
        // get the new password value
        string memory actualPassword = passwordStore.getPassword();
        // assert the password is the same stored by the random address
        assertEq(actualPassword, expectedPassword);
    }
```

</details>


**Recommended Mitigation**: The function `PasswordStore::setPassword` should be access controlled for only the owner. This means that only the owner of the contract should be able to call this function. This can be done using access control mechanisms such as roles or permissions.

The code below should be implemented to ensure that only the owner can call this function

```javascript
    if (msg.sender != s_owner) {
        revert PasswordStore__NotOwner();
    }
```
------

<!-- # Medium
# Low  -->

# Informational

### [I-1] The `PasswordStore::getPassword` function natspec indicates a parameter that doesn't exist, causing the natspec to be incorrect

**Description**: 
```javascript
    /*
     * @notice This allows only the owner to retrieve the password.
    //  @audit - 'newPassword' param is not used.
@>  * @param newPassword The new password to set.
     */
    function getPassword() external view returns (string memory) {
        if (msg.sender != s_owner) {
            revert PasswordStore__NotOwner();
        }
        return s_password;
    }
```

The `PasswordStore::getPassword` function signature is `getPassword()` which the natspec say it should be `getPassword(string)`.

**Impact**: The natspec is incorrect.

**Recommended Mitigation**: Remove the incorrect natspec line.

```diff
- * @param newPassword The new password to set.
```
<!-- # Gas  -->