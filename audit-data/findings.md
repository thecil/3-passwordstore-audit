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