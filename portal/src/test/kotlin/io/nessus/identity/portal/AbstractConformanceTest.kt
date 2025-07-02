package io.nessus.identity.portal

import io.ktor.server.engine.*
import io.nessus.identity.service.ConfigProvider
import io.nessus.identity.service.LoginContext
import org.junit.jupiter.api.TestInstance
import org.openqa.selenium.By
import org.openqa.selenium.Dimension
import org.openqa.selenium.Point
import org.openqa.selenium.WebDriver
import org.openqa.selenium.chrome.ChromeDriver
import org.openqa.selenium.chrome.ChromeOptions
import org.openqa.selenium.support.ui.WebDriverWait
import java.time.Duration

/**
 * brew install --cask google-chrome
 * brew install chromedriver
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
open class AbstractConformanceTest : AbstractActionsTest() {

    lateinit var embeddedServer: EmbeddedServer<*, *>
    lateinit var driver: WebDriver

    fun startPortalServer() {
        System.setProperty("webdriver.chrome.driver", "/opt/homebrew/bin/chromedriver")
        val options = ChromeOptions().apply {
            addArguments("--headless=new")
        }
        driver = ChromeDriver(options)
        driver.manage().timeouts().implicitlyWait(Duration.ofSeconds(10))

        val screenSize = java.awt.Toolkit.getDefaultToolkit().screenSize
        val screenWidth = screenSize.width
        val screenHeight = screenSize.height

        // Move to right half
        driver.manage().window().position = Point(screenWidth / 2, 0)
        driver.manage().window().size = Dimension(screenWidth / 2, screenHeight)

        embeddedServer = PortalServer().createServer()
        embeddedServer.start(wait = false)
    }

    fun stopPortalServer() {
        driver.quit()
        embeddedServer.stop(3000, 5000)
    }

    fun nextStep(millis: Long = 1000) {
        Thread.sleep(millis)
    }

    fun authEndpointUri(ctx: LoginContext): String {
        val authUri = "${ConfigProvider.authEndpointUri}/${ctx.subjectId}"
        return authUri
    }

    fun walletEndpointUri(ctx: LoginContext): String {
        val walletUri = "${ConfigProvider.walletEndpointUri}/${ctx.subjectId}"
        return walletUri
    }

    fun issuerEndpointUri(ctx: LoginContext): String {
        val issuerUri = "${ConfigProvider.issuerEndpointUri}/${ctx.subjectId}"
        return issuerUri
    }

    fun awaitCheckboxResult(checkboxId: String, buttonText: String) : Boolean {

        val wait = WebDriverWait(driver, Duration.ofSeconds(10))

        val checkbox = driver.findElement(By.id(checkboxId))
        checkbox.findElement(By.xpath("following-sibling::button[contains(text(), '$buttonText')]")).click()
        nextStep()

        val labelResult = wait.until {
            val label = checkbox.findElement(By.xpath("following-sibling::label[@for='$checkboxId']/span[1]"))
            label.text == "Yes"
        }
        return labelResult
    }
}
