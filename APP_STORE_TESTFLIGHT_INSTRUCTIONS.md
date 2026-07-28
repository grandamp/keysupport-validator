# Publishing an Invite-Only Beta to iOS TestFlight

Unlike Android, where you can directly distribute an `.apk` file for users to sideload, **Apple strictly prohibits sideloading**. An iOS device will refuse to install an app that isn't cryptographically signed for its specific hardware UUID or distributed through Apple's official channels.

To distribute the iOS version of the KeySupport Validator to testers, you must use Apple's **TestFlight** system.

### Prerequisites
*   An active **Apple Developer Program** membership ($99/year).
*   A Mac running **Xcode**.
*   An **App Store Connect** account (included with your Developer Program membership).

### Step 1: Prepare the App in Xcode
1. Open the project in Xcode.
2. Go to the project settings by clicking the root `KeySupportValidator` file in the left navigator.
3. Under the **Signing & Capabilities** tab, ensure you have selected your development team and that the **Near Field Communication Tag Reading** capability is active.
4. Under the **General** tab, increment the **Version** (e.g., `1.0.1`) and the **Build** number (e.g., `2`). *Note: App Store Connect will reject uploads if the Build number is not strictly incremented over previous uploads.*

### Step 2: Create the App in App Store Connect
1. Log into [App Store Connect](https://appstoreconnect.apple.com/).
2. Go to **My Apps** and click the **+** button to select **New App**.
3. Fill out the basic details (Name, Language, Bundle ID, and SKU). Ensure the Bundle ID matches exactly what is in your Xcode project.

### Step 3: Archive and Upload
1. Back in Xcode, change the active run destination (at the top center of the window) from a Simulator to **Any iOS Device (arm64)**.
2. From the top menu bar, select **Product > Archive**.
3. Xcode will compile the app and open the **Organizer** window when finished.
4. Select your new archive and click **Distribute App** on the right side.
5. Choose **App Store Connect** as the method, and follow the prompts to automatically upload the build to Apple's servers.

### Step 4: Export Compliance and Processing
1. Return to [App Store Connect](https://appstoreconnect.apple.com/) and go to your app.
2. Click on the **TestFlight** tab.
3. Your uploaded build will appear under **Builds > iOS**. It will briefly say "Processing".
4. Once processing completes, click on the build. Apple requires you to answer an **Export Compliance Information** questionnaire regarding cryptography. Because the app uses standard cryptography for authentication (PoP validation), you will generally answer "Yes" to using cryptography, and then select the exemption that it is solely for authentication/security purposes.

### Step 5: Invite Internal Testers
*Internal testers are users who are officially part of your App Store Connect team. They get instant access without needing an App Store review.*

1. In the TestFlight tab, go to **Internal Testing** on the left menu and click the **+** to create a group (e.g., "KeySupport Devs").
2. Add your testers by their Apple ID emails.
3. Click the **+** next to "Builds" and assign your uploaded `1.0.1` build to this group.
4. Testers will immediately receive an email inviting them to download the **TestFlight** app from the App Store and install your beta.

### Step 6: Invite External Testers (Optional)
*External testers are standard users who are not part of your App Store Connect team. Adding external testers requires Apple to perform a brief "Beta App Review" (usually takes 1-2 days).*

1. In the TestFlight tab, go to **External Testing** on the left menu and click the **+** to create a group.
2. Fill out the required testing information (what to test, contact email, etc.).
3. Assign the build to the group. Apple will review it.
4. Once approved, you can add testers by email, or generate a **Public Link** (similar to the Google Play opt-in link) that you can paste in an email, Slack, or GitHub Release notes!
