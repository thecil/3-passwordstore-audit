// SPDX-License-Identifier: MIT
pragma solidity 0.8.18;

import {Test, console} from "forge-std/Test.sol";
import {PasswordStore} from "../src/PasswordStore.sol";
import {DeployPasswordStore} from "../script/DeployPasswordStore.s.sol";

contract PasswordStoreTest is Test {
    PasswordStore public passwordStore;
    DeployPasswordStore public deployer;
    address public owner;

    function setUp() public {
        deployer = new DeployPasswordStore();
        passwordStore = deployer.run();
        owner = msg.sender;
    }

    function test_owner_can_set_password() public {
        vm.startPrank(owner);
        string memory expectedPassword = "myNewPassword";
        passwordStore.setPassword(expectedPassword);
        string memory actualPassword = passwordStore.getPassword();
        assertEq(actualPassword, expectedPassword);
    }

    function test_non_owner_reading_password_reverts() public {
        vm.startPrank(address(1));

        vm.expectRevert(PasswordStore.PasswordStore__NotOwner.selector);
        passwordStore.getPassword();
    }

    /*//////////////////////////////////////////////////////////////
                              AUDIT TESTS
    //////////////////////////////////////////////////////////////*/

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
        string memory actualPassword = passwordStore.getPassword();
        // assert the password is the same stored by the random address
        assertEq(actualPassword, expectedPassword);
    }
}
