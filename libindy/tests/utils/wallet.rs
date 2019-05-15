extern crate futures;
extern crate libc;
extern crate libloading;
extern crate os_type;

use serde_json;
use serde_json::Value;

use indy::{ErrorCode, IndyError};
use indy::wallet;

use self::futures::Future;

use utils::{callback, sequence, environment};
use utils::inmem_wallet::InmemWallet;
use utils::domain::wallet::Credentials;
use utils::domain::wallet::Config;

use std::collections::HashSet;
use std::collections::hash_map::HashMap;
use std::env;
use std::sync::Mutex;
use std::ffi::CString;
use self::libc::c_char;

use utils::constants::{TYPE, INMEM_TYPE, WALLET_CREDENTIALS};

use std::path::{Path, PathBuf};

pub fn register_wallet_storage(xtype: &str, force_create: bool) -> Result<(), ErrorCode> {
    lazy_static! {
            static ref REGISERED_WALLETS: Mutex<HashSet<String>> = Default::default();
        }

    let mut wallets = REGISERED_WALLETS.lock().unwrap();

    if wallets.contains(xtype) & !force_create {
        // as registering of plugged wallet with
        return Ok(());
    }

    let (receiver, command_handle, cb) = callback::_closure_to_cb_ec();

    let xxtype = CString::new(xtype).unwrap();

    let err = unsafe {
        indy_register_wallet_storage(
            command_handle,
            xxtype.as_ptr(),
            Some(InmemWallet::create),
            Some(InmemWallet::open),
            Some(InmemWallet::close),
            Some(InmemWallet::delete),
            Some(InmemWallet::add_record),
            Some(InmemWallet::update_record_value),
            Some(InmemWallet::update_record_tags),
            Some(InmemWallet::add_record_tags),
            Some(InmemWallet::delete_record_tags),
            Some(InmemWallet::delete_record),
            Some(InmemWallet::get_record),
            Some(InmemWallet::get_record_id),
            Some(InmemWallet::get_record_type),
            Some(InmemWallet::get_record_value),
            Some(InmemWallet::get_record_tags),
            Some(InmemWallet::free_record),
            Some(InmemWallet::get_storage_metadata),
            Some(InmemWallet::set_storage_metadata),
            Some(InmemWallet::free_storage_metadata),
            Some(InmemWallet::search_records),
            Some(InmemWallet::search_all_records),
            Some(InmemWallet::get_search_total_count),
            Some(InmemWallet::fetch_search_next_record),
            Some(InmemWallet::free_search),
            cb
        )
    };

    wallets.insert(xtype.to_string());

    super::results::result_to_empty(err as i32, receiver)
}

pub fn create_wallet(config: &str, credentials: &str) -> Result<(), IndyError> {
    let (config, credentials) = override_wallet_config_creds(config, credentials, true);

    wallet::create_wallet(&config, &credentials).wait()
}

pub fn open_wallet(config: &str, credentials: &str) -> Result<i32, IndyError> {
    let (config, credentials) = override_wallet_config_creds(config, credentials, false);

    wallet::open_wallet(&config, &credentials).wait()
}

pub fn create_and_open_wallet(storage_type: Option<&str>) -> Result<i32, IndyError> {
    let config = json!({
            "id": format!("default-wallet_id-{}", sequence::get_next_id()),
            "storage_type": storage_type.unwrap_or(TYPE)
        }).to_string();

    create_wallet(&config, WALLET_CREDENTIALS)?;
    open_wallet(&config, WALLET_CREDENTIALS)
}

pub fn create_and_open_default_wallet() -> Result<i32, IndyError> {
    let config = json!({
            "id": format!("default-wallet_id-{}", sequence::get_next_id()),
            "storage_type": TYPE
        }).to_string();

    create_wallet(&config, WALLET_CREDENTIALS)?;
    open_wallet(&config, WALLET_CREDENTIALS)
}

pub fn create_and_open_plugged_wallet() -> Result<i32, IndyError> {
    let config = json!({
            "id": format!("default-wallet_id-{}", sequence::get_next_id()),
            "storage_type": INMEM_TYPE
        }).to_string();

    register_wallet_storage("inmem", false).unwrap();
    create_wallet(&config, WALLET_CREDENTIALS)?;
    open_wallet(&config, WALLET_CREDENTIALS)
}

pub fn delete_wallet(config: &str, credentials: &str) -> Result<(), IndyError> {
    let (config, credentials) = override_wallet_config_creds(config, credentials, false);

    wallet::delete_wallet(&config, &credentials).wait()
}

pub fn close_wallet(wallet_handle: i32) -> Result<(), IndyError> {
    wallet::close_wallet(wallet_handle).wait()
}

/* 
 * Wrapper to ensure a wallet is closed when it goes out of scope
 * (i.e. if the unit test didn't shut down cleanly)
 */
pub struct WalletHandleWrapper {
    pub handle: i32,
}
impl ::std::ops::Drop for WalletHandleWrapper {
    fn drop(&mut self) {
        // close wallet; ignore result in case we are closing it twice
        let _res = close_wallet(self.handle);
    }
}

pub fn export_wallet(wallet_handle: i32, export_config_json: &str) -> Result<(), IndyError> {
    wallet::export_wallet(wallet_handle, export_config_json).wait()
}

pub fn import_wallet(config: &str, credentials: &str, import_config: &str) -> Result<(), IndyError> {
    wallet::import_wallet(config, credentials, import_config).wait()
}

pub fn export_wallet_path() -> PathBuf {
    environment::tmp_file_path("export_file")
}

pub fn prepare_export_wallet_config(path: &Path) -> String {
    let json = json!({
            "path": path.to_str().unwrap(),
            "key": "export_key",
        });
    serde_json::to_string(&json).unwrap()
}

pub fn generate_wallet_key(config: Option<&str>) -> Result<String, IndyError> {
    wallet::generate_wallet_key(config).wait()
}

extern {
    #[no_mangle]
    pub fn indy_register_wallet_storage(command_handle: i32,
                                        type_: *const c_char,
                                        create: Option<WalletCreate>,
                                        open: Option<WalletOpen>,
                                        close: Option<WalletClose>,
                                        delete: Option<WalletDelete>,
                                        add_record: Option<WalletAddRecord>,
                                        update_record_value: Option<WalletUpdateRecordValue>,
                                        update_record_tags: Option<WalletUpdateRecordTags>,
                                        add_record_tags: Option<WalletAddRecordTags>,
                                        delete_record_tags: Option<WalletDeleteRecordTags>,
                                        delete_record: Option<WalletDeleteRecord>,
                                        get_record: Option<WalletGetRecord>,
                                        get_record_id: Option<WalletGetRecordId>,
                                        get_record_type: Option<WalletGetRecordType>,
                                        get_record_value: Option<WalletGetRecordValue>,
                                        get_record_tags: Option<WalletGetRecordTags>,
                                        free_record: Option<WalletFreeRecord>,
                                        get_storage_metadata: Option<WalletGetStorageMetadata>,
                                        set_storage_metadata: Option<WalletSetStorageMetadata>,
                                        free_storage_metadata: Option<WalletFreeStorageMetadata>,
                                        search_records: Option<WalletSearchRecords>,
                                        search_all_records: Option<WalletSearchAllRecords>,
                                        get_search_total_count: Option<WalletGetSearchTotalCount>,
                                        fetch_search_next_record: Option<WalletFetchSearchNextRecord>,
                                        free_search: Option<WalletFreeSearch>,
                                        cb: Option<ResponseEmptyCB>) -> ErrorCode;
}

pub type WalletCreate = extern fn(name: *const c_char,
                                  config: *const c_char,
                                  credentials_json: *const c_char,
                                  metadata: *const c_char) -> ErrorCode;
pub type WalletOpen = extern fn(name: *const c_char,
                                config: *const c_char,
                                credentials_json: *const c_char,
                                storage_handle_p: *mut i32) -> ErrorCode;
pub type WalletClose = extern fn(storage_handle: i32) -> ErrorCode;
pub type WalletDelete = extern fn(name: *const c_char,
                                  config: *const c_char,
                                  credentials_json: *const c_char) -> ErrorCode;
pub type WalletAddRecord = extern fn(storage_handle: i32,
                                     type_: *const c_char,
                                     id: *const c_char,
                                     value: *const u8,
                                     value_len: usize,
                                     tags_json: *const c_char) -> ErrorCode;
pub type WalletUpdateRecordValue = extern fn(storage_handle: i32,
                                             type_: *const c_char,
                                             id: *const c_char,
                                             value: *const u8,
                                             value_len: usize, ) -> ErrorCode;
pub type WalletUpdateRecordTags = extern fn(storage_handle: i32,
                                            type_: *const c_char,
                                            id: *const c_char,
                                            tags_json: *const c_char) -> ErrorCode;
pub type WalletAddRecordTags = extern fn(storage_handle: i32,
                                         type_: *const c_char,
                                         id: *const c_char,
                                         tags_json: *const c_char) -> ErrorCode;
pub type WalletDeleteRecordTags = extern fn(storage_handle: i32,
                                            type_: *const c_char,
                                            id: *const c_char,
                                            tag_names_json: *const c_char) -> ErrorCode;
pub type WalletDeleteRecord = extern fn(storage_handle: i32,
                                        type_: *const c_char,
                                        id: *const c_char) -> ErrorCode;
pub type WalletGetRecord = extern fn(storage_handle: i32,
                                     type_: *const c_char,
                                     id: *const c_char,
                                     options_json: *const c_char,
                                     record_handle_p: *mut i32) -> ErrorCode;
pub type WalletGetRecordId = extern fn(storage_handle: i32,
                                       record_handle: i32,
                                       record_id_p: *mut *const c_char) -> ErrorCode;
pub type WalletGetRecordType = extern fn(storage_handle: i32,
                                         record_handle: i32,
                                         record_type_p: *mut *const c_char) -> ErrorCode;
pub type WalletGetRecordValue = extern fn(storage_handle: i32,
                                          record_handle: i32,
                                          record_value_p: *mut *const u8,
                                          record_value_len_p: *mut usize) -> ErrorCode;
pub type WalletGetRecordTags = extern fn(storage_handle: i32,
                                         record_handle: i32,
                                         record_tags_p: *mut *const c_char) -> ErrorCode;
pub type WalletFreeRecord = extern fn(storage_handle: i32,
                                      record_handle: i32) -> ErrorCode;
pub type WalletGetStorageMetadata = extern fn(storage_handle: i32,
                                              metadata_p: *mut *const c_char,
                                              metadata_handle: *mut i32) -> ErrorCode;
pub type WalletSetStorageMetadata = extern fn(storage_handle: i32,
                                              metadata_p: *const c_char) -> ErrorCode;
pub type WalletFreeStorageMetadata = extern fn(storage_handle: i32,
                                               metadata_handle: i32) -> ErrorCode;
pub type WalletSearchRecords = extern fn(storage_handle: i32,
                                         type_: *const c_char,
                                         query_json: *const c_char,
                                         options_json: *const c_char,
                                         search_handle_p: *mut i32) -> ErrorCode;
pub type WalletSearchAllRecords = extern fn(storage_handle: i32,
                                            search_handle_p: *mut i32) -> ErrorCode;
pub type WalletGetSearchTotalCount = extern fn(storage_handle: i32,
                                               search_handle: i32,
                                               total_count_p: *mut usize) -> ErrorCode;
pub type WalletFetchSearchNextRecord = extern fn(storage_handle: i32,
                                                 search_handle: i32,
                                                 record_handle_p: *mut i32) -> ErrorCode;
pub type WalletFreeSearch = extern fn(storage_handle: i32,
                                      search_handle: i32) -> ErrorCode;

pub type ResponseEmptyCB = extern fn(xcommand_handle: i32, err: i32);


/*
 * Update wallet config based on supplied configuration,
 *     *only if* "storage_type" is not already provided.
 */
pub fn override_wallet_config_creds(config: &str, credentials: &str, load_dynalib: bool) -> (String, String) {
    // if storge_type is explicit then bail
    let result: serde_json::Result<Config> = serde_json::from_str(config);

    match result {
        Ok(check_config) => {
            if let Some(_) = check_config.storage_type {
                return (config.to_owned(), credentials.to_owned());
            }

            // check for default configs for postgres plugin
            let env_var = "STG_USE";
            let storage_config = match env::var(env_var) {
                Ok(var) => {
                    match var.to_lowercase().as_ref() {
                        "postgres" => postgres_lib_test_overrides(),
                        _ => wallet_storage_overrides()
                    }
                },
                Err(_) => wallet_storage_overrides()
            };

            // if no config is provided at all then bail
            if !any_overrides(&storage_config) {
                return (config.to_owned(), credentials.to_owned());
            }

            // load dynamic library if requested
            if load_dynalib {
                // TODO ignore error (for now)
                let _ = load_storage_library_config(&storage_config); //.unwrap();
            }

            // update config and credentials
            let config = override_wallet_configuration(config, &storage_config);
            let credentials = override_wallet_credentials(credentials, &storage_config);

            return (config, credentials);
        },
        Err(_) => {
            return (config.to_owned(), credentials.to_owned());
        }
    }
}

/*
 * Dynamically loads the specified library and registers storage, based on provided config
 */
pub fn load_storage_library_config(storage_config: &HashMap<String, Option<String>>) -> Result<(), ()> {
    match storage_config.get("STG_LIB") {
        Some(slibrary) => match slibrary {
            Some(library) => {
                let stg_type: String = match storage_config.get("STG_TYPE") {
                    Some(styp) => match styp {
                        Some(typ) => typ.clone(),
                        None => "".to_string()
                    },
                    None => "".to_string()
                };
                let initializer: String = match storage_config.get("STG_INIT") {
                    Some(spfx) => match spfx {
                        Some(pfx) => pfx.clone(),
                        None => "".to_string()
                    },
                    None => "".to_string()
                };
                load_storage_library(&stg_type[..], &library[..], &initializer[..])
            },
            None => Ok(())
        },
        None => Ok(())
    }
}

/*
 * Dynamically loads the specified library and registers storage
 */
pub fn load_storage_library(_stg_type: &str, library: &str, initializer: &str) -> Result<(), ()> {
    println!("Loading {} {} {}", _stg_type, library, initializer);
    let lib_res = _load_lib(library);
    match lib_res {
        Ok(lib) => {
            unsafe {
                let init_func: libloading::Symbol<unsafe extern fn() -> ErrorCode> = lib.get(initializer.as_bytes()).unwrap();

                match init_func() {
                    ErrorCode::Success => println!("Plugin has been loaded: \"{}\"", library),
                    _ => return Err(println!("Plugin has not been loaded: \"{}\"", library))
                }
            }
        },
        Err(_) => return Err(println!("Plugin has not been loaded: \"{}\"", library))
    }

    Ok(())
}

#[cfg(any(unix))]
fn _load_lib(library: &str) -> libloading::Result<libloading::Library> {
    libloading::os::unix::Library::open(Some(library), self::libc::RTLD_NOW | self::libc::RTLD_NODELETE)
        .map(libloading::Library::from)
}

#[cfg(any(not(unix)))]
fn _load_lib(library: &str) -> libloading::Result<libloading::Library> {
    libloading::Library::new(library)
}

/*
 * Update the given configuration string based on supplied overrides
 */
pub fn override_wallet_configuration(config: &str, overrides: &HashMap<String, Option<String>>) -> String {
    let mut config: Config = serde_json::from_str(config).unwrap();

    match overrides.get("STG_TYPE") {
        Some(stype) => match stype {
            Some(wtype) => {
                config.storage_type = Some(wtype.clone());
            },
            None => ()
        },
        None => ()
    }
    match overrides.get("STG_CONFIG") {
        Some(sconfig) => match sconfig {
            Some(wconfig) => {
                let v: Value = serde_json::from_str(&wconfig[..]).unwrap();
                config.storage_config = Some(v.clone());
            },
            None => ()
        },
        None => ()
    }

    serde_json::to_string(&config).unwrap()
}

/*
 * Update the given credentials string based on supplied overrides
 */
pub fn override_wallet_credentials(creds: &str, overrides: &HashMap<String, Option<String>>) -> String {
    let mut creds: Credentials = serde_json::from_str(creds).unwrap();

    match overrides.get("STG_CREDS") {
        Some(screds) => match screds {
            Some(wcreds) => {
                let v: Value = serde_json::from_str(&wcreds[..]).unwrap();
                creds.storage_credentials = Some(v.clone());
            },
            None => ()
        },
        None => ()
    }

    serde_json::to_string(&creds).unwrap()
}

/*
 * Returns wallet storage configuation dynamically configured via environment variables:
 * STG_CONFIG - json configuration string to pass to the wallet on creation and open
 * STG_CREDS - json credentials string to pass to the wallet on creation and open
 * STG_TYPE - storage type to create (must match type in library)
 * STG_LIB - c-callable library to load (contains a plug-in storage)
 *         - if specified will dynamically load and register a wallet storage
 * STG_INIT - library initializer function to call
 */
pub fn wallet_storage_overrides() -> HashMap<String, Option<String>> {
    let mut storage_config = HashMap::new();
    let env_vars = vec!["STG_CONFIG", "STG_CREDS", "STG_TYPE", "STG_LIB", "STG_INIT"];

    for env_var in env_vars.iter() {
        match env::var(env_var) {
            Ok(var) => storage_config.insert(env_var.to_string(), Some(var.to_string())),
            Err(_) => storage_config.insert(env_var.to_string(), None)
        };
    }

    storage_config
}

pub fn any_overrides(storage_config: &HashMap<String, Option<String>>) -> bool {
    for (_key, val) in storage_config {
        if let Some(_) = val {
            return true;
        }
    }
    return false;
}

pub fn get_postgres_storage_plugin()  -> String {
    let os = os_type::current_platform();
    let osfile = match os.os_type {
        os_type::OSType::OSX => "libindystrgpostgres.dylib",
        os_type::OSType::Unknown => "libindystrgpostgres.dll",
        _ => "libindystrgpostgres.so"
    };
    return osfile.to_owned();
}

pub fn postgres_lib_test_overrides() -> HashMap<String, Option<String>> {
    // Note - libraries be in the directories in LD_LIBRARY_PATH, e.g.:
    //      export LD_LIBRARY_PATH=../samples/storage/storage-inmem/target/debug/:./target/debug/
    let osfile = get_postgres_storage_plugin();

    let mut storage_config = HashMap::new();
    let env_vars = vec!["STG_CONFIG", "STG_CREDS", "STG_TYPE", "STG_LIB", "STG_INIT"];
    storage_config.insert(env_vars[0].to_string(), Some(r#"{"url":"localhost:5432"}"#.to_string()));
    storage_config.insert(env_vars[1].to_string(), Some(r#"{"account":"postgres","password":"mysecretpassword","admin_account":"postgres","admin_password":"mysecretpassword"}"#.to_string()));
    storage_config.insert(env_vars[2].to_string(), Some("postgres_storage".to_string()));
    storage_config.insert(env_vars[3].to_string(), Some(osfile.to_string()));
    storage_config.insert(env_vars[4].to_string(), Some("postgresstorage_init".to_string()));
    storage_config
}
