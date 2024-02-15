# Pimcore Host Header Injection in user invitation link

## Overview

A potential security vulnerability discovered in `pimcore/admin-ui-classic-bundle` version up to v1.3.3 . The vulnerability involves a Host Header Injection in the `invitationLinkAction` function of the UserController, specifically in the way `$loginUrl` trusts user input. 

## Details

The host header from incoming HTTP requests is used unsafely when generating URLs. An attacker can manipulate the HTTP host header in requests to the /admin/user/invitationlink endpoint, resulting in the generation of URLs with the attacker's domain. 

In fact, if a host header is injected in the POST request, the $loginURL parameter is constructed with this unvalidated host header. It is then used to send an invitation email to the provided user.

Here is an excerpt from the affected section of UserController.php file:
```
// /src/Controller/Admin/UserController.php 
    public function invitationLinkAction(Request $request, TranslatorInterface $translator): JsonResponse
    {
            // ..snip..
                $token = Tool\Authentication::generateTokenByUser($user);
                $loginUrl = $this->generateCustomUrl([
                    'token' => $token,
                    'reset' => true,
                ]);

                try {
                    $mail = Tool::getMail([$user->getEmail()], 'Pimcore login invitation for ' . Tool::getHostname());
                    $mail->setIgnoreDebugMode(true);
                    $mail->text("Login to pimcore and change your password using the following link. This temporary login link will expire in  24 hours: \r\n\r\n" . $loginUrl);
                    $mail->send();
      // ..snip..
    }
    // ..snip..
    private function generateCustomUrl(array $params, string $fallbackUrl = 'pimcore_admin_login_check', int $referenceType = UrlGeneratorInterface::ABSOLUTE_URL): string
    {
        try {
            $adminEntryPointRoute = $this->getParameter('pimcore_admin.custom_admin_route_name');

            //try to generate invitation link for custom admin point
            $loginUrl = $this->generateUrl($adminEntryPointRoute, $params, $referenceType);
        } catch (\Exception $e) {
            //use default login check for invitation link
            $loginUrl = $this->generateUrl($fallbackUrl, $params, $referenceType);
        }

        return $loginUrl;
    }
```
The $loginUrl variable is constructed using the generateCustomUrl function. If an attacker injects a malicious host header into a POST request, the resulting $loginUrl will include the malicious domain, and this link is then sent via email to the user.

## Proof of Concept

Here is an example of a request that exploits this vulnerability:
```
POST /admin/user/invitationlink HTTP/1.1 
Host: attacker-domain.evil 
Cookie: PHPSESSID=test
X-pimcore-extjs-version-major: 7
X-pimcore-extjs-version-minor: 0
X-Requested-With: XMLHttpRequest
X-pimcore-csrf-token: 961c37cf60edfdc2eec5a705cb048aaa8c32804d

username=[username of a valid user]
```


The URL in the email will look like: `http://attacker-domain.evil/admin/login/login?token=....`

## Impact

This vulnerability can be used to perform phishing attacks by making the URLs in the invitation links emails point to an attacker-controlled domain.

## Remediation

We recommend validating the host header and ensuring it matches the application's domain. It would also be beneficial to use a default trusted host or hostname if the incoming host header is not recognized or is absent.

Similare vulnerability (CVE-2024-23648) has been fixed in this project by using `UrlGeneratorInterface::ABSOLUTE_URL` (https://github.com/pimcore/admin-ui-classic-bundle/commit/70f2205b5a5ea9584721d4f3e803f4d0dd5e4655)

## Credit

Discovered by @v0lck3r (Oussama RAHALI), Feb 2024.

