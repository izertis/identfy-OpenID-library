import { IssuerMetadataBuilder } from "@/common/builders/index.js";
import { expect, test, describe } from '@jest/globals';

describe("Issuer Metadata", () => {
  describe("With impose https flag", () => {
    test("Should create the Auth Metadata Object", () => {
      expect(
        () => {
          new IssuerMetadataBuilder(
            "https://issuer",
            "https://issuer/credential",
            true
          );
        }
      ).not.toThrow();
    });
    test("Should not allow use http url", () => {
      expect(
        () => {
          new IssuerMetadataBuilder(
            "https://issuer",
            "https://issuer/credential",
            true
          ).withAuthorizationServer("http://auth");
        }
      ).toThrow();
    });
  });

  describe("Without impose https flag", () => {
    test("Should create the Auth Metadata Object", () => {
      expect(
        () => {
          new IssuerMetadataBuilder(
            "http://issuer",
            "http://issuer/credential",
            false
          );
        }
      ).not.toThrow();
    });
    test("Should allow use http url", () => {
      expect(
        () => {
          new IssuerMetadataBuilder(
            "http://issuer",
            "http://issuer/credential",
            false
          ).withAuthorizationServer("http://auth");
        }
      ).not.toThrow();
    });
  });
});
