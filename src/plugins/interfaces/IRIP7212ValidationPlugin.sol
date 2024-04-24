// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

interface IRIP7212ValidationPlugin {
    enum FunctionId {
        RUNTIME_VALIDATION_RIP7212,
        USER_OP_VALIDATION_RIP7212
    }
}