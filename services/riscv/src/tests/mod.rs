use std::{
    cell::RefCell,
    fs::File,
    io::Read,
    ops::{Deref, DerefMut},
    rc::Rc,
    str::FromStr,
    sync::Arc,
};

use protocol::{
    traits::{ServiceResponse, ServiceState},
    types::{Address, Hash, ServiceContext, ServiceContextParams},
    Bytes,
};

use cita_trie::MemoryDB;

use core_storage::{adapter::memory::MemoryAdapter, ImplStorage};
use framework::binding::{
    sdk::{DefaultChainQuerier, DefaultServiceSDK},
    state::{GeneralServiceState, MPTTrie},
};

use crate::{
    types::{
        AddressList, DeployPayload, ExecPayload, GetContractPayload, InitGenesisPayload,
        InterpreterType,
    },
    RiscvService, ServiceError,
};
use asset::AssetService;
use governance::GovernanceService;
use kyc::KycService;
use metadata::MetadataService;
use timestamp::TimestampService;
use transfer_quota::TransferQuotaService;

thread_local! {
    static STATE: Rc<RefCell<GeneralServiceState<MemoryDB>>> = {
        let trie = MPTTrie::new(Arc::new(MemoryDB::default()));
        Rc::new(RefCell::new(GeneralServiceState::new(trie)))
    };
}

macro_rules! service {
    ($service:expr, $method:ident, $ctx:expr) => {{
        let resp = $service.$method($ctx);
        assert!(!resp.is_error(), resp.error_message);

        resp.succeed_data
    }};
    ($service:expr, $method:ident, $ctx:expr, $payload:expr) => {{
        let resp = $service.$method($ctx, $payload);
        assert!(!resp.is_error(), resp.error_message);

        resp.succeed_data
    }};
}

const CYCLE_LIMIT: u64 = 1024 * 1024 * 1024;
const CYCLE_PRICE: u64 = 1;
const CYCLE_USED: u64 = 3;
const NONCE: &str = "0x1122334455667788990012223344556677889900112233445566778899001122";
const TX_HASH: &str = "0x1234112233445566778899001222334455667788990011223344556677889900";
const CALLER: &str = "muta19dddt3retspx298cx9785g27yxxue4k0zmetx3";
const ADMIN: &str = "muta10e0525sfrf53yh2aljmm3sn9jq5njk7llt9agp";

macro_rules! read_code {
    ($path:expr) => {{
        let mut file = File::open($path).expect("open code file");
        let mut buffer = Vec::new();

        file.read_to_end(&mut buffer).expect("read code file");
        hex::encode(Bytes::from(buffer).as_ref())
    }};
}

#[test]
fn test_deploy_and_run() {
    let mut service = TestRiscvService::new();
    let context = TestContext::default().make_admin();

    let code = read_code!("src/tests/simple_storage");

    let deploy_result = service!(service, deploy, context.clone(), DeployPayload {
        code:      code.clone(),
        intp_type: InterpreterType::Binary,
        init_args: "set k init".into(),
    });
    assert_eq!(&deploy_result.init_ret, "");

    // test get_contract
    let address = deploy_result.address;
    let get_contract_resp = service!(service, get_contract, context.clone(), GetContractPayload {
        address:      address.clone(),
        get_code:     true,
        storage_keys: vec![hex::encode("k"), "".to_owned(), "3a".to_owned()],
    });
    assert_eq!(&get_contract_resp.code, &code);
    assert_eq!(&get_contract_resp.storage_values, &vec![
        hex::encode("init"),
        "".to_owned(),
        "".to_owned()
    ]);

    let exec_result = service!(service, exec, context.clone(), ExecPayload {
        address: address.clone(),
        args:    "get k".into(),
    });
    assert_eq!(&exec_result, "init");

    let exec_result = service!(service, exec, context.clone(), ExecPayload {
        address: address.clone(),
        args:    "set k v".into(),
    });
    assert_eq!(&exec_result, "");

    let exec_result = service!(service, exec, context.clone(), ExecPayload {
        address: address.clone(),
        args:    "get k".into(),
    });
    assert_eq!(&exec_result, "v");

    // wrong command
    let exec_result = service.exec(context.clone(), ExecPayload {
        address: address.clone(),
        args:    "clear k v".into(),
    });
    assert!(exec_result.is_error());

    // wrong command 2
    let exec_result = service.exec(context, ExecPayload {
        address,
        args: "set k".into(),
    });
    assert!(exec_result.is_error());
}

#[test]
fn should_not_change_state_by_read_call() {
    let mut service = TestRiscvService::new();
    let mut ctx = TestContext::default();

    let deployed = service!(service, deploy, ctx.make_admin(), DeployPayload {
        code:      read_code!("src/tests/simple_storage"),
        intp_type: InterpreterType::Binary,
        init_args: "set k init".into(),
    });
    assert_eq!(deployed.init_ret, "");

    let inited = service!(service, exec, ctx.make_admin(), ExecPayload {
        address: deployed.address.clone(),
        args:    "get k".into(),
    });

    let called = service.call(ctx.make_admin(), ExecPayload {
        address: deployed.address.clone(),
        args:    "set k v".into(),
    });
    assert_eq!(called.is_error(), true);

    let called = service!(service, call, ctx.make_admin(), ExecPayload {
        address: deployed.address,
        args:    "get k".into(),
    });
    assert_eq!(called, inited, "read call should not change state");
}

#[test]
fn should_not_change_state_through_read_write_chained_invocations() {
    // env_logger::init();

    let mut service = TestRiscvService::new();
    let mut ctx = TestContext::default();

    let deployed = service!(service, deploy, ctx.make_admin(), DeployPayload {
        code:      read_code!("src/tests/write_read"),
        intp_type: InterpreterType::Binary,
        init_args: "".into(),
    });
    assert_eq!(deployed.init_ret, "");

    let called = service.call(ctx.make_admin(), ExecPayload {
        address: deployed.address.clone(),
        args:    format!("f{}", deployed.address.to_string()),
    });
    assert!(called.is_error());

    let msg_resp = service.call(ctx.make_admin(), ExecPayload {
        address: deployed.address.clone(),
        args:    format!("x{}", deployed.address.to_string()),
    });
    assert!(!msg_resp.is_error());
    assert_eq!(
        msg_resp.succeed_data,
        serde_json::to_string("").expect("json encode")
    );
}

#[test]
fn should_allow_change_state_through_write_write_chained_invocations() {
    let mut service = TestRiscvService::new();
    let mut ctx = TestContext::default();

    let deployed = service!(service, deploy, ctx.make_admin(), DeployPayload {
        code:      read_code!("src/tests/write_read"),
        intp_type: InterpreterType::Binary,
        init_args: "".into(),
    });
    assert_eq!(deployed.init_ret, "");

    let called = service.exec(ctx.make_admin(), ExecPayload {
        address: deployed.address.clone(),
        args:    format!("c{}", deployed.address.to_string()),
    });
    println!("{:?}", called);
    assert!(!called.is_error());

    let msg_resp = service.call(ctx.make_admin(), ExecPayload {
        address: deployed.address.clone(),
        args:    "m".into(),
    });
    assert!(!msg_resp.is_error());
    let expect_msg = serde_json::to_string(&msg_resp.succeed_data).expect("encode expect msg");

    let msg_resp = service.call(ctx.make_admin(), ExecPayload {
        address: deployed.address.clone(),
        args:    format!("x{}", deployed.address.to_string()),
    });
    assert!(!msg_resp.is_error());

    assert_eq!(msg_resp.succeed_data, expect_msg);
}

#[test]
fn should_deny_deploy_contract_until_granted_when_authorization_enabled() {
    let mut service = TestRiscvService::new_restricted();
    let mut ctx = TestContext::default();

    let code = read_code!("src/tests/simple_storage");
    let deployed = service.deploy(ctx.make(), DeployPayload {
        code:      code.clone(),
        intp_type: InterpreterType::Binary,
        init_args: "set k init".into(),
    });
    assert!(deployed.is_error());
    assert_eq!(deployed.code, ServiceError::NonAuthorized.code());

    let context = ctx.make_admin();
    let caller = Address::from_str(CALLER).expect("from CALLER");
    let allow_list = vec![caller];
    service!(service, grant_deploy_auth, context.clone(), AddressList {
        addresses: allow_list.clone(),
    });
    assert_eq!(context.get_events().len(), 1);

    let event_name: String = context.get_events()[0].name.parse().expect("parse event");
    assert_eq!(event_name, "GrantAuth");

    let granted = service!(service, check_deploy_auth, ctx.make(), AddressList {
        addresses: allow_list.clone(),
    });
    assert_eq!(granted.addresses, allow_list);

    let deployed = service.deploy(ctx.make(), DeployPayload {
        code,
        intp_type: InterpreterType::Binary,
        init_args: "set k init".into(),
    });
    assert!(!deployed.is_error());
}

#[test]
fn should_require_admin_permission_to_revoke_deploy_auth() {
    let mut service = TestRiscvService::new_restricted();
    let mut ctx = TestContext::default();

    let caller = Address::from_str(CALLER).expect("from CALLER");
    service!(service, grant_deploy_auth, ctx.make_admin(), AddressList {
        addresses: vec![caller.clone()],
    });

    let code = read_code!("src/tests/simple_storage");
    let deployed = service.deploy(ctx.make(), DeployPayload {
        code:      code.clone(),
        intp_type: InterpreterType::Binary,
        init_args: "set k init".into(),
    });
    assert!(!deployed.is_error());

    let revoked = service.revoke_deploy_auth(ctx.make(), AddressList {
        addresses: vec![caller.clone()],
    });
    assert!(revoked.is_error());

    let context = ctx.make_admin();
    let revoked = service.revoke_deploy_auth(context.clone(), AddressList {
        addresses: vec![caller],
    });
    assert!(!revoked.is_error());
    assert_eq!(context.get_events().len(), 1);

    let event_name: String = context.get_events()[0].name.parse().expect("parse event");
    assert_eq!(event_name, "RevokeAuth");

    let deployed = service.deploy(ctx.make(), DeployPayload {
        code,
        intp_type: InterpreterType::Binary,
        init_args: "set k init".into(),
    });
    assert!(deployed.is_error());
    assert_eq!(deployed.code, ServiceError::NonAuthorized.code());
}

#[test]
fn should_deny_exec_contract_until_approved_when_authorization_enabled() {
    let mut service = TestRiscvService::new_restricted();
    let mut ctx = TestContext::default();

    let code = read_code!("src/tests/simple_storage");
    let deployed = service!(service, deploy, ctx.make_admin(), DeployPayload {
        code,
        intp_type: InterpreterType::Binary,
        init_args: "set k init".into(),
    });
    assert_eq!(&deployed.init_ret, "");

    let resp = service.exec(ctx.make(), ExecPayload {
        address: deployed.address.clone(),
        args:    "get k".into(),
    });
    assert!(resp.is_error());
    assert_eq!(resp.code, ServiceError::NonAuthorized.code());

    service!(service, approve_contracts, ctx.make_admin(), AddressList {
        addresses: vec![deployed.address.clone()],
    });

    let resp = service!(service, exec, ctx.make(), ExecPayload {
        address: deployed.address,
        args:    "get k".into(),
    });
    assert_eq!(resp, "init");
}

#[test]
fn should_return_contract_authorization_state_by_get_contract_api() {
    let mut service = TestRiscvService::new_restricted();
    let mut ctx = TestContext::default();

    let code = read_code!("src/tests/simple_storage");
    let deployed = service!(service, deploy, ctx.make_admin(), DeployPayload {
        code,
        intp_type: InterpreterType::Binary,
        init_args: "set k init".into(),
    });
    assert_eq!(&deployed.init_ret, "");

    let contract = service!(service, get_contract, ctx.make(), GetContractPayload {
        address:      deployed.address.clone(),
        get_code:     false,
        storage_keys: vec![],
    });
    assert!(contract.authorizer.is_none());

    let approved = service.approve_contracts(ctx.make_admin(), AddressList {
        addresses: vec![deployed.address.clone()],
    });
    assert!(!approved.is_error());

    let contract = service!(service, get_contract, ctx.make(), GetContractPayload {
        address:      deployed.address,
        get_code:     false,
        storage_keys: vec![],
    });
    assert_eq!(
        contract.authorizer.map(|a| a.to_string()),
        Some(ADMIN.to_owned())
    );
}

#[test]
fn should_require_admin_permission_to_revoke_contracts() {
    let mut service = TestRiscvService::new_restricted();
    let mut ctx = TestContext::default();

    let code = read_code!("src/tests/simple_storage");
    let deployed = service!(service, deploy, ctx.make_admin(), DeployPayload {
        code,
        intp_type: InterpreterType::Binary,
        init_args: "set k init".into(),
    });
    assert_eq!(&deployed.init_ret, "");

    service!(service, approve_contracts, ctx.make_admin(), AddressList {
        addresses: vec![deployed.address.clone()],
    });

    let revoked = service.revoke_contracts(ctx.make(), AddressList {
        addresses: vec![deployed.address.clone()],
    });
    assert!(revoked.is_error());
    assert_eq!(revoked.code, ServiceError::NonAuthorized.code());

    let context = ctx.make_admin();
    let approved = service.revoke_contracts(context.clone(), AddressList {
        addresses: vec![deployed.address],
    });
    assert!(!approved.is_error());
    assert_eq!(context.get_events().len(), 1);

    let event_name: String = context.get_events()[0].name.parse().expect("parse event");
    assert_eq!(event_name, "RevokeContract");
}

#[test]
fn should_require_admin_permission_to_approve_contracts() {
    let mut service = TestRiscvService::new_restricted();
    let mut ctx = TestContext::default();

    let code = read_code!("src/tests/simple_storage");
    let deployed = service!(service, deploy, ctx.make_admin(), DeployPayload {
        code,
        intp_type: InterpreterType::Binary,
        init_args: "set k init".into(),
    });
    assert_eq!(&deployed.init_ret, "");

    let approved = service.approve_contracts(ctx.make(), AddressList {
        addresses: vec![deployed.address.clone()],
    });
    assert!(approved.is_error());
    assert_eq!(approved.code, ServiceError::NonAuthorized.code());

    let context = ctx.make_admin();
    let approved = service.approve_contracts(context.clone(), AddressList {
        addresses: vec![deployed.address],
    });
    assert!(!approved.is_error());
    assert_eq!(context.get_events().len(), 1);

    let event_name: String = context.get_events()[0].name.parse().expect("parse event");
    assert_eq!(event_name, "ApproveContract");
}

#[test]
fn should_count_cycles_on_failed_contract_execution() {
    let mut service = TestRiscvService::new();
    let mut ctx = TestContext::default();

    // We use write_read contract, call c() should fail because
    // read call cannot change state.
    let deployed = service!(service, deploy, ctx.make_admin(), DeployPayload {
        code:      read_code!("src/tests/write_read"),
        intp_type: InterpreterType::Binary,
        init_args: "".into(),
    });
    assert_eq!(deployed.init_ret, "");

    let ctx = ctx.make_admin();
    let before_cycles = ctx.get_cycles_used();

    let called = service.call(ctx.clone(), ExecPayload {
        address: deployed.address.clone(),
        args:    format!("c{}", deployed.address.to_string()),
    });

    assert!(called.is_error());
    assert!(before_cycles < ctx.get_cycles_used());
}

#[test]
fn should_also_return_assert_message_on_assert_failed() {
    let mut service = TestRiscvService::new();
    let mut ctx = TestContext::default();

    let deployed = service!(service, deploy, ctx.make_admin(), DeployPayload {
        code:      read_code!("src/tests/assert"),
        intp_type: InterpreterType::Binary,
        init_args: "".into(),
    });
    assert_eq!(deployed.init_ret, "");

    // Directly call assert failed
    let called = service.call(ctx.make_admin(), ExecPayload {
        address: deployed.address.clone(),
        args:    format!("a{}", deployed.address.to_string()),
    });

    assert!(called.is_error());
    assert_eq!(
        called.error_message,
        "Assert failed: 1 should never bigger than 2"
    );

    // Contract call assert failed
    let called = service.call(ctx.make_admin(), ExecPayload {
        address: deployed.address.clone(),
        args:    format!("b{}", deployed.address.to_string()),
    });

    assert!(called.is_error());
    assert_eq!(
        called.error_message,
        "Assert failed: 1 should never bigger than 2"
    );
}

type SDKType = DefaultServiceSDK<
    GeneralServiceState<MemoryDB>,
    DefaultChainQuerier<ImplStorage<MemoryAdapter>>,
>;
type KycServiceType = KycService<SDKType>;
type TimestampServiceType = TimestampService<SDKType>;

type TransferQuotaServiceType = TransferQuotaService<SDKType, KycServiceType, TimestampServiceType>;

type GovernanceServiceType = GovernanceService<AssetServiceType, MetadataServiceType, SDKType>;

type MetadataServiceType = MetadataService<SDKType>;

type AssetServiceType = AssetService<SDKType, TransferQuotaServiceType>;

type RiscvServiceType =
    RiscvService<AssetServiceType, GovernanceServiceType, KycServiceType, SDKType>;

struct TestRiscvService(RiscvServiceType);

impl TestRiscvService {
    pub fn new() -> TestRiscvService {
        let storage = ImplStorage::new(Arc::new(MemoryAdapter::new()));
        let chain_db = DefaultChainQuerier::new(Arc::new(storage));
        let chain_db = Rc::new(chain_db);

        let trie = MPTTrie::new(Arc::new(MemoryDB::new(false)));
        let state = GeneralServiceState::new(trie);
        let state = Rc::new(RefCell::new(state));

        let sdk = DefaultServiceSDK::new(Rc::clone(&state), Rc::clone(&chain_db));

        let kyc_service = KycService::new(DefaultServiceSDK::new(
            Rc::clone(&state),
            Rc::clone(&chain_db),
        ));

        let timestamp_service = TimestampService::new(DefaultServiceSDK::new(
            Rc::clone(&state),
            Rc::clone(&chain_db),
        ));

        let asset_service = AssetServiceType::new(
            DefaultServiceSDK::new(Rc::clone(&state), Rc::clone(&chain_db)),
            None,
        );

        let asset_service2 = AssetServiceType::new(
            DefaultServiceSDK::new(Rc::clone(&state), Rc::clone(&chain_db)),
            None,
        );

        let metadata_service = MetadataServiceType::new(DefaultServiceSDK::new(
            Rc::clone(&state),
            Rc::clone(&chain_db),
        ));

        let governance_service = GovernanceServiceType::new(
            DefaultServiceSDK::new(Rc::clone(&state), Rc::clone(&chain_db)),
            asset_service2,
            metadata_service,
        );

        Self(RiscvService::new(
            DefaultServiceSDK::new(Rc::clone(&state), Rc::clone(&chain_db)),
            asset_service,
            governance_service,
            kyc_service,
        ))
    }

    pub fn new_restricted() -> TestRiscvService {
        let mut service = Self::new();

        let admin = Address::from_str(ADMIN).expect("admin");
        service.init_genesis(InitGenesisPayload {
            enable_authorization: true,
            admin:                admin.clone(),
            deploy_auth:          vec![admin],
        });

        service
    }
}

impl Deref for TestRiscvService {
    type Target = RiscvServiceType;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for TestRiscvService {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

struct TestContext {
    count:  usize,
    height: u64,
}

impl Default for TestContext {
    fn default() -> Self {
        TestContext {
            count:  1,
            height: 1,
        }
    }
}

impl TestContext {
    fn make(&mut self) -> ServiceContext {
        ServiceContext::new(self.new_params())
    }

    fn make_admin(&mut self) -> ServiceContext {
        let mut params = self.new_params();
        params.caller = Address::from_str(ADMIN).expect("ctx admin");
        ServiceContext::new(params)
    }

    fn new_params(&mut self) -> ServiceContextParams {
        self.count += 1;
        self.height += 1;

        let tx_hash = Hash::from_hex(TX_HASH).unwrap();

        ServiceContextParams {
            tx_hash:         Some(tx_hash),
            nonce:           Some(Hash::from_hex(NONCE).unwrap()),
            cycles_limit:    CYCLE_LIMIT,
            cycles_price:    CYCLE_PRICE,
            cycles_used:     Rc::new(RefCell::new(CYCLE_USED)),
            caller:          Address::from_str(CALLER).expect("ctx caller"),
            height:          self.height,
            timestamp:       0,
            extra:           Some(Bytes::from("extra")),
            service_name:    "service_name".to_owned(),
            service_method:  "service_method".to_owned(),
            service_payload: "service_payload".to_owned(),
            events:          Rc::new(RefCell::new(vec![])),
        }
    }
}
