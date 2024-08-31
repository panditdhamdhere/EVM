use std::collections::HashMap;
use sha3::{Keccak256, Digest};
use primitive_types::U256 as u256;

#[derive(Clone)]
struct Address([u8; 20]);

struct Environment {
    caller: Address,
    value: u256,
    data: Vec<u8>,
}

struct Contract {
    code: Vec<u8>,
    storage: HashMap<u256, u256>,
}

struct Log {
    address: Address,
    topics: Vec<u256>,
    data: Vec<u8>,
}

struct EVM {
    stack: Vec<u256>,
    memory: Vec<u8>,
    pc: usize,
    gas: u64,
    environment: Environment,
    contracts: HashMap<Address, Contract>,
    current_contract: Address,
    logs: Vec<Log>,
}

impl EVM {
    fn new(gas_limit: u64, caller: Address, value: u256, data: Vec<u8>) -> Self {
        EVM {
            stack: Vec::new(),
            memory: vec![0; 1024],
            pc: 0,
            gas: gas_limit,
            environment: Environment { caller, value, data },
            contracts: HashMap::new(),
            current_contract: Address([0; 20]),
            logs: Vec::new(),
        }
    }

    fn execute(&mut self, address: Address) -> Result<(), String> {
        self.current_contract = address.clone();
        let contract = self.contracts.get(&address).ok_or("Contract not found")?;
        let bytecode = &contract.code;

        while self.pc < bytecode.len() {
            let opcode = bytecode[self.pc];
            self.pc += 1;

            if self.gas < 1 {
                return Err("Out of gas".to_string());
            }
            self.gas -= 1;

            match opcode {
                0x00 => break, // STOP
                0x01 => self.add()?,
                0x02 => self.mul()?,
                0x03 => self.sub()?,
                0x04 => self.div()?,
                0x10 => self.lt()?,
                0x11 => self.gt()?,
                0x14 => self.eq()?,
                0x50 => self.pop()?,
                0x51 => self.mload()?,
                0x52 => self.mstore()?,
                0x54 => self.sload()?,
                0x55 => self.sstore()?,
                0x56 => self.jump()?,
                0x57 => self.jumpi()?,
                0x60 => self.push1(bytecode)?,
                0xf0 => self.create()?,
                0xf1 => self.call()?,
                0xf2 => self.callcode()?,
                0xf3 => self.return_()?,
                0xa0 => self.log(0)?,
                0xa1 => self.log(1)?,
                0xa2 => self.log(2)?,
                0xa3 => self.log(3)?,
                0xa4 => self.log(4)?,
                0x20 => self.sha3()?,
                0xf4 => self.delegatecall()?,
                0xf5 => self.create2()?,
                _ => return Err(format!("Unknown opcode: {:x}", opcode)),
            }
        }
        Ok(())
    }

    fn add(&mut self) -> Result<(), String> {
        let a = self.stack.pop().ok_or("Stack underflow")?;
        let b = self.stack.pop().ok_or("Stack underflow")?;
        self.stack.push(a.overflowing_add(b).0);
        Ok(())
    }

    fn mul(&mut self) -> Result<(), String> {
        let a = self.stack.pop().ok_or("Stack underflow")?;
        let b = self.stack.pop().ok_or("Stack underflow")?;
        self.stack.push(a.overflowing_mul(b).0);
        Ok(())
    }

    fn sub(&mut self) -> Result<(), String> {
        let a = self.stack.pop().ok_or("Stack underflow")?;
        let b = self.stack.pop().ok_or("Stack underflow")?;
        self.stack.push(a.overflowing_sub(b).0);
        Ok(())
    }

    fn div(&mut self) -> Result<(), String> {
        let a = self.stack.pop().ok_or("Stack underflow")?;
        let b = self.stack.pop().ok_or("Stack underflow")?;
        self.stack.push(if b == 0 { 0.into() } else { a / b.into() });
        Ok(())
    }

    fn pop(&mut self) -> Result<(), String> {
        self.stack.pop();
        Ok(())
    }

    fn mload(&mut self) -> Result<(), String> {
        let offset = self.stack.pop().ok_or("Stack underflow")? as usize;
        let value = u256::from_big_endian(&self.memory[offset..offset+32]);
        self.stack.push(value);
        Ok(())
    }

    fn mstore(&mut self) -> Result<(), String> {
        let offset = self.stack.pop().ok_or("Stack underflow")? as usize;
        let value = self.stack.pop().ok_or("Stack underflow")?;
        value.to_big_endian(&mut self.memory[offset..offset+32]);
        Ok(())
    }

    fn sload(&mut self) -> Result<(), String> {
        self.gas = self.gas.checked_sub(800).ok_or("Out of gas")?; // SLOAD costs 800 gas
        let key = self.stack.pop().ok_or("Stack underflow")?;
        let value = self.contracts.get(&self.current_contract)
            .ok_or("Contract not found")?
            .storage
            .get(&key)
            .cloned()
            .unwrap_or_else(|| 0.into());
        self.stack.push(value);
        Ok(())
    }

    fn sstore(&mut self) -> Result<(), String> {
        let key = self.stack.pop().ok_or("Stack underflow")?;
        let value = self.stack.pop().ok_or("Stack underflow")?;
        let contract = self.contracts.get_mut(&self.current_contract)
            .ok_or("Contract not found")?;
        
        let old_value = contract.storage.get(&key).cloned().unwrap_or_else(|| 0.into());
        if old_value == 0.into() && value != 0.into() {
            self.gas = self.gas.checked_sub(20000).ok_or("Out of gas")?; // Setting new value costs 20000 gas
        } else if old_value != 0.into() && value == 0.into() {
            self.gas = self.gas.checked_add(15000).ok_or("Gas overflow")?; // Refund for clearing storage
        } else {
            self.gas = self.gas.checked_sub(5000).ok_or("Out of gas")?; // Modifying existing value costs 5000 gas
        }
        
        contract.storage.insert(key, value);
        Ok(())
    }

    fn lt(&mut self) -> Result<(), String> {
        let a = self.stack.pop().ok_or("Stack underflow")?;
        let b = self.stack.pop().ok_or("Stack underflow")?;
        self.stack.push(if a < b { 1.into() } else { 0.into() });
        Ok(())
    }

    fn gt(&mut self) -> Result<(), String> {
        let a = self.stack.pop().ok_or("Stack underflow")?;
        let b = self.stack.pop().ok_or("Stack underflow")?;
        self.stack.push(if a > b { 1.into() } else { 0.into() });
        Ok(())
    }

    fn eq(&mut self) -> Result<(), String> {
        let a = self.stack.pop().ok_or("Stack underflow")?;
        let b = self.stack.pop().ok_or("Stack underflow")?;
        self.stack.push(if a == b { 1.into() } else { 0.into() });
        Ok(())
    }

    fn jump(&mut self) -> Result<(), String> {
        let dest = self.stack.pop().ok_or("Stack underflow")?;
        self.pc = dest.as_usize();
        Ok(())
    }

    fn jumpi(&mut self) -> Result<(), String> {
        let dest = self.stack.pop().ok_or("Stack underflow")?;
        let condition = self.stack.pop().ok_or("Stack underflow")?;
        if condition != 0.into() {
            self.pc = dest.as_usize();
        }
        Ok(())
    }

    fn push1(&mut self, bytecode: &[u8]) -> Result<(), String> {
        if self.pc >= bytecode.len() {
            return Err("Unexpected end of bytecode".to_string());
        }
        let value = u256::from(bytecode[self.pc]);
        self.stack.push(value);
        self.pc += 1;
        Ok(())
    }

    fn create(&mut self) -> Result<(), String> {
        let value = self.stack.pop().ok_or("Stack underflow")?;
        let offset = self.stack.pop().ok_or("Stack underflow")? as usize;
        let length = self.stack.pop().ok_or("Stack underflow")? as usize;

        let code = self.memory[offset..offset+length].to_vec();
        let new_address = self.generate_contract_address();

        let new_contract = Contract {
            code,
            storage: HashMap::new(),
        };

        self.contracts.insert(new_address.clone(), new_contract);
        self.stack.push(u256::from(&new_address.0[..]));

        Ok(())
    }

    fn call(&mut self) -> Result<(), String> {
        let gas = self.stack.pop().ok_or("Stack underflow")?;
        let address = Address(self.stack.pop().ok_or("Stack underflow")?.to_be_bytes()[12..].try_into().unwrap());
        let value = self.stack.pop().ok_or("Stack underflow")?;
        let args_offset = self.stack.pop().ok_or("Stack underflow")? as usize;
        let args_length = self.stack.pop().ok_or("Stack underflow")? as usize;
        let ret_offset = self.stack.pop().ok_or("Stack underflow")? as usize;
        let ret_length = self.stack.pop().ok_or("Stack underflow")? as usize;

        let args = self.memory[args_offset..args_offset+args_length].to_vec();

        // Check if it's a precompiled contract
        if address.0[..19] == [0; 19] && address.0[19] <= 4 {
            let result = self.execute_precompiled(&address);
            match result {
                Ok(_) => {
                    self.memory[ret_offset..ret_offset+ret_length].copy_from_slice(&self.memory[..ret_length]);
                    self.stack.push(1.into()); // Success
                }
                Err(_) => {
                    self.stack.push(0.into()); // Failure
                }
            }
        } else {
            // Existing code for calling regular contracts
            let mut sub_evm = EVM::new(
                gas.as_u64(),
                self.current_contract.clone(),
                value,
                args,
            );
            sub_evm.contracts = self.contracts.clone();

            match sub_evm.execute(address) {
                Ok(_) => {
                    self.gas -= gas.as_u64() - sub_evm.gas;
                    self.memory[ret_offset..ret_offset+ret_length].copy_from_slice(&sub_evm.memory[..ret_length]);
                    self.stack.push(1.into()); // Success
                }
                Err(_) => {
                    self.stack.push(0.into()); // Failure
                }
            }

            self.contracts = sub_evm.contracts;
        }
        Ok(())
    }

    fn callcode(&mut self) -> Result<(), String> {
        // Similar to call, but uses the storage of the calling contract
        // Implementation left as an exercise
        Ok(())
    }

    fn return_(&mut self) -> Result<(), String> {
        let offset = self.stack.pop().ok_or("Stack underflow")? as usize;
        let length = self.stack.pop().ok_or("Stack underflow")? as usize;

        self.memory.truncate(offset + length);
        self.memory.drain(..offset);

        Ok(())
    }

    fn generate_contract_address(&self) -> Address {
        let mut hasher = Keccak256::new();
        hasher.update(&self.current_contract.0);
        // In a real implementation, we would use a nonce here
        // For simplicity, we're using a fixed value
        hasher.update(&[0u8; 32]);
        let result = hasher.finalize();
        Address(result[12..].try_into().unwrap())
    }

    fn log(&mut self, num_topics: usize) -> Result<(), String> {
        let offset = self.stack.pop().ok_or("Stack underflow")? as usize;
        let length = self.stack.pop().ok_or("Stack underflow")? as usize;

        let mut topics = Vec::new();
        for _ in 0..num_topics {
            topics.push(self.stack.pop().ok_or("Stack underflow")?);
        }

        let data = self.memory[offset..offset+length].to_vec();

        self.logs.push(Log {
            address: self.current_contract.clone(),
            topics,
            data,
        });

        // Gas cost: 375 + 375 * num_topics + 8 * length
        let gas_cost = 375 + 375 * num_topics + 8 * length;
        self.gas = self.gas.checked_sub(gas_cost as u64).ok_or("Out of gas")?;

        Ok(())
    }

    fn sha3(&mut self) -> Result<(), String> {
        let offset = self.stack.pop().ok_or("Stack underflow")? as usize;
        let length = self.stack.pop().ok_or("Stack underflow")? as usize;

        let data = &self.memory[offset..offset+length];
        let mut hasher = Keccak256::new();
        hasher.update(data);
        let result = hasher.finalize();

        let value = u256::from_big_endian(&result);
        self.stack.push(value);

        // Gas cost: 30 + 6 * (length / 32)
        let gas_cost = 30 + 6 * ((length + 31) / 32);
        self.gas = self.gas.checked_sub(gas_cost as u64).ok_or("Out of gas")?;

        Ok(())
    }

    fn delegatecall(&mut self) -> Result<(), String> {
        let gas = self.stack.pop().ok_or("Stack underflow")?;
        let address = Address(self.stack.pop().ok_or("Stack underflow")?.to_be_bytes()[12..].try_into().unwrap());
        let args_offset = self.stack.pop().ok_or("Stack underflow")? as usize;
        let args_length = self.stack.pop().ok_or("Stack underflow")? as usize;
        let ret_offset = self.stack.pop().ok_or("Stack underflow")? as usize;
        let ret_length = self.stack.pop().ok_or("Stack underflow")? as usize;

        let args = self.memory[args_offset..args_offset+args_length].to_vec();

        let called_contract = self.contracts.get(&address).ok_or("Contract not found")?;
        let code = called_contract.code.clone();

        let mut sub_evm = EVM::new(
            gas.as_u64(),
            self.environment.caller.clone(),
            self.environment.value,
            args,
        );
        sub_evm.contracts = self.contracts.clone();
        sub_evm.current_contract = self.current_contract.clone();
        sub_evm.memory = self.memory.clone();

        // Execute the code of the called contract in the context of the calling contract
        let result = sub_evm.execute_code(&code);

        match result {
            Ok(_) => {
                self.gas -= gas.as_u64() - sub_evm.gas;
                self.memory[ret_offset..ret_offset+ret_length].copy_from_slice(&sub_evm.memory[..ret_length]);
                // Update the storage of the calling contract
                if let Some(contract) = self.contracts.get_mut(&self.current_contract) {
                    contract.storage = sub_evm.contracts.get(&self.current_contract).unwrap().storage.clone();
                }
                self.stack.push(1.into()); // Success
            }
            Err(_) => {
                self.stack.push(0.into()); // Failure
            }
        }

        Ok(())
    }

    fn execute_code(&mut self, code: &[u8]) -> Result<(), String> {
        let mut pc = 0;
        while pc < code.len() {
            let opcode = code[pc];
            pc += 1;

            if self.gas < 1 {
                return Err("Out of gas".to_string());
            }
            self.gas -= 1;

            match opcode {
                0x00 => break, // STOP
                0x01 => self.add()?,
                0x02 => self.mul()?,
                0x03 => self.sub()?,
                0x04 => self.div()?,
                0x10 => self.lt()?,
                0x11 => self.gt()?,
                0x14 => self.eq()?,
                0x50 => self.pop()?,
                0x51 => self.mload()?,
                0x52 => self.mstore()?,
                0x54 => self.sload()?,
                0x55 => self.sstore()?,
                0x56 => self.jump()?,
                0x57 => self.jumpi()?,
                0x60 => self.push1(&code[pc..])?,
                0xf0 => self.create()?,
                0xf1 => self.call()?,
                0xf2 => self.callcode()?,
                0xf3 => self.return_()?,
                0xa0 => self.log(0)?,
                0xa1 => self.log(1)?,
                0xa2 => self.log(2)?,
                0xa3 => self.log(3)?,
                0xa4 => self.log(4)?,
                0x20 => self.sha3()?,
                0xf4 => self.delegatecall()?,
                _ => return Err(format!("Unknown opcode: {:x}", opcode)),
            }
        }
        Ok(())
    }

    fn execute_precompiled(&mut self, address: &Address) -> Result<(), String> {
        match address.0 {
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] => self.ecrecover(),
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2] => self.sha256(),
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3] => self.ripemd160(),
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4] => self.identity(),
            _ => Err("Unknown precompiled contract".to_string()),
        }
    }

    fn ecrecover(&mut self) -> Result<(), String> {
        // Simplified implementation
        self.gas = self.gas.checked_sub(3000).ok_or("Out of gas")?;
        // In a real implementation, this would perform ECDSA recovery
        self.stack.push(0.into()); // Push a dummy address
        Ok(())
    }

    fn sha256(&mut self) -> Result<(), String> {
        let offset = self.stack.pop().ok_or("Stack underflow")? as usize;
        let size = self.stack.pop().ok_or("Stack underflow")? as usize;
        let data = &self.memory[offset..offset+size];

        self.gas = self.gas.checked_sub(60 + 12 * ((size + 31) / 32)).ok_or("Out of gas")?;

        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();

        self.memory[0..32].copy_from_slice(&result);
        self.stack.push(32.into()); // Push the size of the result
        Ok(())
    }

    fn ripemd160(&mut self) -> Result<(), String> {
        let offset = self.stack.pop().ok_or("Stack underflow")? as usize;
        let size = self.stack.pop().ok_or("Stack underflow")? as usize;
        let data = &self.memory[offset..offset+size];

        self.gas = self.gas.checked_sub(600 + 120 * ((size + 31) / 32)).ok_or("Out of gas")?;

        use ripemd::{Ripemd160, Digest};
        let mut hasher = Ripemd160::new();
        hasher.update(data);
        let result = hasher.finalize();

        self.memory[0..20].copy_from_slice(&result);
        self.memory[20..32].fill(0); // Pad with zeros to 32 bytes
        self.stack.push(32.into()); // Push the size of the result (padded to 32 bytes)
        Ok(())
    }

    fn identity(&mut self) -> Result<(), String> {
        let offset = self.stack.pop().ok_or("Stack underflow")? as usize;
        let size = self.stack.pop().ok_or("Stack underflow")? as usize;

        self.gas = self.gas.checked_sub(15 + 3 * ((size + 31) / 32)).ok_or("Out of gas")?;

        // Simply copy the input to the output
        self.memory[0..size].copy_from_slice(&self.memory[offset..offset+size]);
        self.stack.push(size.into()); // Push the size of the result
        Ok(())
    }

    fn create2(&mut self) -> Result<(), String> {
        let value = self.stack.pop().ok_or("Stack underflow")?;
        let offset = self.stack.pop().ok_or("Stack underflow")? as usize;
        let length = self.stack.pop().ok_or("Stack underflow")? as usize;
        let salt = self.stack.pop().ok_or("Stack underflow")?;

        let code = self.memory[offset..offset+length].to_vec();
        let new_address = self.generate_create2_address(&code, &salt);

        let new_contract = Contract {
            code,
            storage: HashMap::new(),
        };

        self.contracts.insert(new_address.clone(), new_contract);
        self.stack.push(u256::from(&new_address.0[..]));

        // Gas cost: 32000 + 200*length
        let gas_cost = 32000 + 200 * length;
        self.gas = self.gas.checked_sub(gas_cost as u64).ok_or("Out of gas")?;

        Ok(())
    }

    fn generate_create2_address(&self, code: &[u8], salt: &u256) -> Address {
        let mut hasher = Keccak256::new();
        hasher.update(&[0xff]);
        hasher.update(&self.current_contract.0);
        salt.to_big_endian(&mut [0u8; 32]);
        hasher.update(&salt.to_be_bytes());
        hasher.update(&Keccak256::digest(code));
        let result = hasher.finalize();
        Address(result[12..].try_into().unwrap())
    }
}

fn main() {
    let caller = Address([1; 20]);
    let mut evm = EVM::new(1000000, caller, 0.into(), vec![]);

    // Create a contract that uses CREATE2 to deploy another contract
    let contract_code = vec![
        0x60, 0x0a, // PUSH1 10 (length of contract to create)
        0x60, 0x00, // PUSH1 0 (offset of contract code in memory)
        0x60, 0x00, // PUSH1 0 (value to send)
        0x60, 0x00, // PUSH1 0 (salt)
        0xf5,       // CREATE2
        0x60, 0x00, // PUSH1 0 (offset to store result)
        0x52,       // MSTORE
    ];

    // Simple contract to be created: just returns 42
    let create2_contract = vec![
        0x60, 0x2a, // PUSH1 42
        0x60, 0x00, // PUSH1 0
        0x52,       // MSTORE
        0x60, 0x20, // PUSH1 32
        0x60, 0x00, // PUSH1 0
        0xf3,       // RETURN
    ];

    let contract_address = Address([2; 20]);
    evm.contracts.insert(contract_address.clone(), Contract {
        code: contract_code,
        storage: HashMap::new(),
    });

    // Set the contract to be created in memory
    evm.memory[0..create2_contract.len()].copy_from_slice(&create2_contract);

    match evm.execute(contract_address) {
        Ok(_) => {
            println!("Contract execution completed.");
            println!("Created contract address: 0x{}", hex::encode(&evm.memory[0..20]));
        },
        Err(e) => println!("Contract execution failed: {}", e),
    }
    println!("Remaining gas: {}", evm.gas);

    // Now let's try to execute the created contract
    let created_address = Address(evm.memory[0..20].try_into().unwrap());
    match evm.execute(created_address) {
        Ok(_) => {
            println!("Created contract execution completed.");
            println!("Return value: {}", u256::from_big_endian(&evm.memory[0..32]));
        },
        Err(e) => println!("Created contract execution failed: {}", e),
    }
}
