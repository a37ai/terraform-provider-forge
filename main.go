package main

import (
	"context"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	forgeprovider "github.com/a37ai/terraform-provider-forge/internal/provider"
)

var version = "dev"

func main() {
	err := providerserver.Serve(context.Background(), forgeprovider.New(version), providerserver.ServeOpts{
		Address: "registry.terraform.io/a37ai/forge",
	})
	if err != nil {
		log.Fatal(err)
	}
}
