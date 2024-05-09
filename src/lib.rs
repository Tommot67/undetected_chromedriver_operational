use rand::Rng;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::fs::PermissionsExt;
use std::process::{Child, Command};
use std::error::Error;
use std::thread;
use std::time::Duration;
use async_trait::async_trait;

pub use thirtyfour::*;
use thirtyfour::error::WebDriverResult;
use thirtyfour::prelude::ElementWaitable;

pub struct UndetectedChrome {
    webdriver: WebDriver,
    child: Child,
}

/// true for custom User-Agent and CLOUDFLAREBYPASSER = HEADLESS(true)
pub enum UndetectedChromeUsage {
    HEADLESS(bool),
    WINDOWS(bool),
    CLOUDFLAREBYPASSER,
}


async fn chrome(usage: UndetectedChromeUsage) -> Result<(WebDriver, Child ), Box<dyn std::error::Error>> {
    let os = std::env::consts::OS;
    if std::path::Path::new("chromedriver").exists()
        || std::path::Path::new("chromedriver.exe").exists()
    {
        println!("ChromeDriver already exists!");
    } else {
        println!("ChromeDriver does not exist! Fetching...");
        let client = reqwest::Client::new();
        fetch_chromedriver(&client).await.unwrap();
    }
    let chromedriver_executable = match os {
        "linux" => "chromedriver_PATCHED",
        "macos" => "chromedriver_PATCHED",
        "windows" => "chromedriver_PATCHED.exe",
        _ => panic!("Unsupported OS!"),
    };
    match !std::path::Path::new(chromedriver_executable).exists() {
        true => {
            println!("Starting ChromeDriver executable patch...");
            let file_name = if cfg!(windows) {
                "chromedriver.exe"
            } else {
                "chromedriver"
            };
            let f = std::fs::read(file_name).unwrap();
            let mut new_chromedriver_bytes = f.clone();
            let mut total_cdc = String::from("");
            let mut cdc_pos_list = Vec::new();
            let mut is_cdc_present = false;
            let mut patch_ct = 0;
            for i in 0..f.len() - 3 {
                if "cdc_"
                    == format!(
                        "{}{}{}{}",
                        f[i] as char,
                        f[i + 1] as char,
                        f[i + 2] as char,
                        f[i + 3] as char
                    )
                    .as_str()
                {
                    for x in i + 4..i + 22 {
                        total_cdc.push_str(&(f[x] as char).to_string());
                    }
                    is_cdc_present = true;
                    cdc_pos_list.push(i);
                    total_cdc = String::from("");
                }
            }
            match is_cdc_present {
                true => println!("Found cdcs!"),
                false => println!("No cdcs were found!"),
            }
            let get_random_char = || -> char {
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    .chars()
                    .collect::<Vec<char>>()[rand::thread_rng().gen_range(0..48)]
            };

            for i in cdc_pos_list {
                for x in i + 4..i + 22 {
                    new_chromedriver_bytes[x] = get_random_char() as u8;
                }
                patch_ct += 1;
            }
            println!("Patched {} cdcs!", patch_ct);

            println!("Starting to write to binary file...");
            let _file = std::fs::File::create(chromedriver_executable).unwrap();
            match std::fs::write(chromedriver_executable, new_chromedriver_bytes) {
                Ok(_res) => {
                    println!("Successfully wrote patched executable to 'chromedriver_PATCHED'!",)
                }
                Err(err) => println!("Error when writing patch to file! Error: {}", err),
            };
        }
        false => {
            println!("Detected patched chromedriver executable!");
        }
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let mut perms = std::fs::metadata(chromedriver_executable)
            .unwrap()
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(chromedriver_executable, perms).unwrap();
    }
    println!("Starting chromedriver...");
    let port: usize = rand::thread_rng().gen_range(2000..5000);
    let child = Command::new(format!("./{}", chromedriver_executable))
        .arg(format!("--port={}", port))
        .spawn()
        .expect("Failed to start chromedriver!");
    let mut caps = DesiredCapabilities::chrome();
    caps.add_default_capabilities();


    match usage {
        UndetectedChromeUsage::HEADLESS(true)  =>  {
            caps.set_headless_version().await.unwrap();
            caps.add_chrome_arg("user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36").unwrap();
        },
        UndetectedChromeUsage::WINDOWS(true) => caps.add_chrome_arg("user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36").unwrap(),
        UndetectedChromeUsage::HEADLESS(false) => {
            caps.set_headless_version().await.unwrap();
        },
        UndetectedChromeUsage::WINDOWS(false) => {},
        UndetectedChromeUsage::CLOUDFLAREBYPASSER => {
            caps.set_headless_version().await.unwrap();
            caps.add_chrome_arg("user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36").unwrap();
        }
    }
    let mut driver = None;
    let mut attempt = 0;
    while driver.is_none() && attempt < 20 {
        attempt += 1;
        match WebDriver::new(&format!("http://localhost:{}", port), caps.clone()).await {
            Ok(d) => driver = Some(d),
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(250)).await,
        }
    }
    let driver = driver.unwrap();
    Ok((driver, child))
}
async fn fetch_chromedriver(client: &reqwest::Client) -> Result<(), Box<dyn std::error::Error>> {
    let os = std::env::consts::OS;

    let installed_version = get_chrome_version(os).await?;
    let chromedriver_url: String;
    if installed_version.as_str() >= "114" {
        // Fetch the correct version
        let url = "https://googlechromelabs.github.io/chrome-for-testing/latest-versions-per-milestone.json";
        let resp = client.get(url).send().await?;
        let body = resp.bytes().await?;
        let json = serde_json::from_slice::<serde_json::Value>(&body)?;
        let version = json["milestones"][installed_version]["version"]
            .as_str()
            .unwrap();

        // Fetch the chromedriver binary
        chromedriver_url = match os {
            "linux" => format!(
                //https://storage.googleapis.com/chrome-for-testing-public/124.0.6367.155/win64/chrome-win64.zip
                "https://storage.googleapis.com/chrome-for-testing-public/{}/{}/{}",
                version, "linux64", "chromedriver-linux64.zip"
            ),
            "macos" => format!(
                "https://storage.googleapis.com/chrome-for-testing-public/{}/{}/{}",
                version, "mac-x64", "chromedriver-mac-x64.zip"
            ),
            "windows" => format!(
                "https://storage.googleapis.com/chrome-for-testing-public/{}/{}/{}",
                version, "win64", "chromedriver-win64.zip"
            ),
            _ => panic!("Unsupported OS!"),
        };
    } else {
        let resp = client
            .get(format!(
                "https://chromedriver.storage.googleapis.com/LATEST_RELEASE_{}",
                installed_version
            ))
            .send()
            .await?;
        let body = resp.text().await?;
        chromedriver_url = match os {
            "linux" => format!(
                "https://chromedriver.storage.googleapis.com/{}/chromedriver_linux64.zip",
                body
            ),
            "windows" => format!(
                "https://chromedriver.storage.googleapis.com/{}/chromedriver_win32.zip",
                body
            ),
            "macos" => format!(
                "https://chromedriver.storage.googleapis.com/{}/chromedriver_mac64.zip",
                body
            ),
            _ => panic!("Unsupported OS!"),
        };
    }

    let resp = client.get(&chromedriver_url).send().await?;
    let body = resp.bytes().await?;

    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(body))?;
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let outpath = file.mangled_name();
        if file.name().ends_with('/') {
            std::fs::create_dir_all(&outpath)?;
        } else {
            let outpath_relative = outpath.file_name().unwrap();
            let mut outfile = std::fs::File::create(outpath_relative)?;
            std::io::copy(&mut file, &mut outfile)?;
        }
    }
    Ok(())
}
async fn get_chrome_version(os: &str) -> Result<String, Box<dyn std::error::Error>> {
    //println!("Getting installed Chrome version...");
    let command = match os {
        "linux" => Command::new("/usr/bin/google-chrome")
            .arg("--version")
            .output()?,
        "macos" => Command::new("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
            .arg("--version")
            .output()?,
        "windows" => Command::new("powershell")
            .arg("-c")
            .arg("(Get-Item 'C:/Program Files/Google/Chrome/Application/chrome.exe').VersionInfo")
            .output()?,
        _ => panic!("Unsupported OS!"),
    };
    let output = String::from_utf8(command.stdout)?;

    let version = output
        .lines()
        .flat_map(|line| line.chars().filter(|&ch| ch.is_ascii_digit()))
        .take(3)
        .collect::<String>();

    //println!("Currently installed Chrome version: {}", version);
    Ok(version)
}
#[async_trait]
pub trait CustomTrait {
    fn add_default_capabilities(&mut self);
    async fn set_headless_version(&mut self) -> WebDriverResult<()>;
    fn set_disable_blink_features(&mut self) -> WebDriverResult<()>;
    fn set_disable_popup_blocking(&mut self) -> WebDriverResult<()>;
    fn set_disable_extensions(&mut self) -> WebDriverResult<()>;
    fn set_window_size(&mut self, width: u32, height: u32) -> WebDriverResult<()>;
    fn set_disable_infobars(&mut self) -> WebDriverResult<()>;
    fn set_start_maximized(&mut self) -> WebDriverResult<()>;
    fn set_exclude_switches(&mut self) -> WebDriverResult<()>;
}
#[async_trait]
impl CustomTrait for ChromeCapabilities {
    fn add_default_capabilities(&mut self) {
        self.set_no_sandbox().unwrap();
        self.set_disable_dev_shm_usage().unwrap();
        self.set_disable_web_security().unwrap();
        self.set_disable_blink_features().unwrap();
        self.set_disable_popup_blocking().unwrap();
        self.set_disable_extensions().unwrap();
        self.set_window_size(1920,1080).unwrap();
        self.set_disable_infobars().unwrap();
        self.set_start_maximized().unwrap();
        self.set_exclude_switches().unwrap();
    }
    async fn set_headless_version(&mut self) -> WebDriverResult<()> {
        if get_chrome_version(std::env::consts::OS).await.unwrap().parse::<u32>().unwrap() >= 108 {
            self.add_chrome_arg("--headless=new")
        }
        else {
            self.add_chrome_arg("--headless=chrome")
        }
    }
    fn set_disable_blink_features(&mut self) -> WebDriverResult<()> {
        self.add_chrome_arg("--disable-blink-features=AutomationControlled")
    }

    fn set_disable_popup_blocking(&mut self) -> WebDriverResult<()> {
        self.add_chrome_arg("--disable-popup-blocking")
    }

    fn set_disable_extensions(&mut self) -> WebDriverResult<()> {
        self.add_chrome_arg("--disable-extensions")
    }

    fn set_window_size(&mut self, width: u32, height: u32) -> WebDriverResult<()> {
        self.add_chrome_arg(format!("--window-size={},{}", width, height).as_str())
    }
    fn set_disable_infobars(&mut self) -> WebDriverResult<()> {
        self.add_chrome_arg("--disable-infobars")
    }
    fn set_start_maximized(&mut self) -> WebDriverResult<()> {
        self.add_chrome_arg("--start-maximized")
    }
    fn set_exclude_switches(&mut self) -> WebDriverResult<()> {
        self.add_chrome_option("excludeSwitches", ["enable-automation"])
    }
}
#[async_trait::async_trait]
pub trait Chrome {
    async fn new(usage: UndetectedChromeUsage) -> Self;
    async fn bypass_cloudflare(
        &self,
        url: &str,
    ) -> Result<(), Box<dyn Error>>;

    async fn kill(&mut self);
    fn borrow(&self) -> WebDriver;
    async fn goto(&self, url: &str) -> Result<(), Box<dyn Error>>;
}
#[async_trait::async_trait]
impl Chrome for UndetectedChrome {
    async fn new(usage: UndetectedChromeUsage) -> UndetectedChrome {
        let (webdriver , child) = chrome(usage).await.unwrap();
        UndetectedChrome { webdriver, child }
    }
    async fn bypass_cloudflare(
        &self,
        url: &str,
    ) -> Result<(), Box<dyn Error>> {
        let driver = self.borrow();
        self.goto(url).await?;

        driver.enter_frame(0).await?;

        let button = driver.find(By::Css("#challenge-stage")).await?;

        button.wait_until().clickable().await?;
        thread::sleep(Duration::from_secs(2));
        button.click().await?;

        thread::sleep(Duration::from_secs(2));

        Ok(())
    }
    async fn kill(&mut self) {
        self.borrow().quit().await.unwrap();
        self.child.kill().unwrap();
    }
    fn borrow(&self) -> WebDriver {
        self.webdriver.to_owned()
    }
    async fn goto(&self, url: &str) -> Result<(), Box<dyn Error>> {
        let driver = self.borrow();
        driver
            .execute(
                &format!(r#"window.open("{}", "_blank");"#, url),
                vec![],
            )
            .await?;

        thread::sleep(Duration::from_secs(3));

        let first_window = driver
        .windows()
        .await?
        .first()
        .expect("Unable to get first windows")
        .clone();

        driver.switch_to_window(first_window).await?;
        driver.close_window().await?;
        let first_window = driver
            .windows()
            .await?
            .last()
            .expect("Unable to get last windows")
            .clone();
        driver.switch_to_window(first_window).await?;

        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn it_works() {
        let mut client = UndetectedChrome::new(UndetectedChromeUsage::CLOUDFLAREBYPASSER).await;

        match client.bypass_cloudflare("https://www3.yggtorrent.cool").await {
            Ok(_) => println!("Cloudflare bypassed successfully!"),
            Err(e) => {
                println!("Error: {}", e);
                client.kill().await;
            },
        }

        let webdriver = client.borrow();

        match webdriver.get_all_cookies().await {
            Ok(cookies) => {
                let last_cookie = cookies.last().map(|c| c.to_owned().into_owned());

                for (_, cookie) in cookies.iter().enumerate() {
                    print!("{}={}", cookie.name(), cookie.value());
                    if Some(cookie) != last_cookie.as_ref() {
                        print!("; ");
                    }
                }
                println!();
            },
            Err(e) => {
                println!("Error: {}", e);
                client.kill().await;
            }
        }

        client.kill().await;
    }
}
