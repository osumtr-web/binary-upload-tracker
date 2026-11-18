const puppeteer = require('puppeteer');
const path = require('path');

(async () => {
  const browser = await puppeteer.launch({
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage']
  });

  const page = await browser.newPage();
  await page.setViewport({ width: 1920, height: 1080, deviceScaleFactor: 2 });

  const htmlPath = path.resolve(__dirname, 'demo.html');
  await page.goto(`file://${htmlPath}`, { waitUntil: 'networkidle0', timeout: 30000 });

  // Wait for rendering to complete
  await page.waitForSelector('.log-row', { timeout: 10000 });
  await new Promise(r => setTimeout(r, 500));

  const outputPath = path.resolve(__dirname, 'docs', 'screenshot.png');
  await page.screenshot({
    path: outputPath,
    fullPage: false,
    type: 'png'
  });

  console.log(`Screenshot saved to ${outputPath}`);
  await browser.close();
})();