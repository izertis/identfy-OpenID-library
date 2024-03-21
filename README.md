<p align="center">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="./docs/img/identfy-logo-dark.svg">
      <source media="(prefers-color-scheme: light)" srcset="./docs/img/identfy-logo-light.svg">
      <img alt="identfy" src="./docs/img/identfy.png" width="350" style="max-width: 100%;">
    </picture>
</p>

<p align="center">
  <h4>
    An all-in-one solution to take control of your digital identity
  </h4>
</p>

<br/>

**[identfy](https://github.com/izertis/identfy)** is a combination of various products that enable building user-centric solutions.


# identfy OpenID library

**identfy OpenID library** is a generalist and stateless implementation of OpenID4VCI and OpenID4VP. The library defines the methods and tools needed to manage an authorization and authentication process, as well as to issue W3C credentials. For its correct operation, the user must provide callbacks for different issues, especially related to the signature and additional validation processes to be performed.

The issuing of credentials is done through a different component than the one used for authentication and authorization, so in practice a user interested only in these issues could also benefit from the library.


## Table of content:

- [How to start using it](#usage)
- [Development guide](#development-guide)
- [License](#license)
- [Trademark](#trademark)


## Usage

### Prerequisites

For the use of the library only Node with a version equal or higher than 16 is required.

### Step by step

You can import it on your own project.

Soon, it will be availabme as an npm package.


## Development guide

If you are interested on testing and building it by yourself or you would like to contribute, you can find here the [development guide](./docs/GETTING_STARTED.md)


## Help and Documentation

- *Contact:* send an email to blockchain@izertis.com
- [Github discussions](https://github.com/izertis/identfy-OpenID-library/discussions) - Help and general questions about this project


# License
This software is dual-licensed; you can choose between the terms of the [Affero GNU General Public License version 3 (AGPL-3.0)](./LICENSES/agpl-3.0.txt) or a [commercial license](./LICENSES/commercial.txt). Look at [LICENSE](./LICENSE.md) file for more information.


# Trademark
**identfy** and its logo are registered trademarks of [Izertis](https://www.izertis.com)
