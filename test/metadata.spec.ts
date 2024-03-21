import { expect } from "chai";
import { IssuerMetadataBuilder } from "../src/index.js";

describe("Issuer Metadata", () => {
  context("With impose https flag", () => {
    it("Should create the Auth Metadata Object", () => {
      expect(
        () => {
          new IssuerMetadataBuilder(
            "https://issuer",
            "https://issuer/credential",
            true
          );
        }
      ).to.not.throw();
    });
    it("Should not allow use http url", () => {
      expect(
        () => {
          new IssuerMetadataBuilder(
            "https://issuer",
            "https://issuer/credential",
            true
          ).withAuthorizationServer("http://auth");
        }
      ).to.throw();
    });
  });

  context("Without impose https flag", () => {
    it("Should create the Auth Metadata Object", () => {
      expect(
        () => {
          new IssuerMetadataBuilder(
            "http://issuer",
            "http://issuer/credential",
            false
          );
        }
      ).to.not.throw();
    });
    it("Should allow use http url", () => {
      expect(
        () => {
          new IssuerMetadataBuilder(
            "http://issuer",
            "http://issuer/credential",
            false
          ).withAuthorizationServer("http://auth");
        }
      ).to.not.throw();
    });
  });
});
