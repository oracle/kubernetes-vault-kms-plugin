/*
Copyright © 2018, Oracle and/or its affiliates. All rights reserved.

The Universal Permissive License (UPL), Version 1.0
*/

package main

import (
	"flag"
	log "github.com/sirupsen/logrus"
	"net"
	"os"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
        pb "k8s.io/apiserver/pkg/storage/value/encrypt/envelope/v1beta1"
	"github.com/oracle/kubernetes-vault-kms-plugin/vault"
	"golang.org/x/sys/unix"
)

const (
	port = ":50051"
)

type CommandArgs struct {
	socketFile            string
	vaultConfig           string
}

var vaultServer *vault.VaultEnvelopeService 
// server is used to implement kms plugin grpc server.
type server struct{}

func (s *server) Version(ctx context.Context, request *pb.VersionRequest) (*pb.VersionResponse, error) {
	log.Infof("Version information requested by API server")
	return &pb.VersionResponse{Version: "v1beta1", RuntimeName: "vault", RuntimeVersion: "0.1.0"}, nil
}

func (s *server) Decrypt(ctx context.Context, request *pb.DecryptRequest) (*pb.DecryptResponse, error) { 
	plain, err := vaultServer.Decrypt(request.Cipher)
	if err != nil{
		log.Warnf("Decrypt error: %v", err)
		return nil, err
	}
	return &pb.DecryptResponse{Plain: plain}, nil
}

func (s *server) Encrypt(ctx context.Context, request *pb.EncryptRequest) (*pb.EncryptResponse, error) {
	cipher, err := vaultServer.Encrypt(request.Plain)
	if err != nil{
                log.Warnf("Encrypt error: %v", err)
		return nil, err
        }
	return &pb.EncryptResponse{Cipher: cipher}, nil
}

func parseCmd() CommandArgs {
	socketFile := flag.String("socketFile", "", "socket file that gRpc server listens to")
	vaultConfig := flag.String("vaultConfig", "", "vault config file location")
	flag.Parse()
	
	if len(*socketFile) == 0 {
		log.Fatal("socketFile parameter not specified")
	}

	if len(*vaultConfig) == 0 {
		log.Fatal("vaultConfig parameter not specified")
        }


        cmdArgs := CommandArgs{
		socketFile:            *socketFile,
		vaultConfig:           *vaultConfig,
	}
	return cmdArgs
}


func main() {
	/**********************parse command line arguments*******************/
	cmdArgs := parseCmd()
      

	// TODO clean sock file first
	err := unix.Unlink(cmdArgs.socketFile)
	f, err := os.Open(cmdArgs.vaultConfig)
	if err != nil {
		log.Fatal("failed to read config file")
	}
	vs, err2 := vault.KMSFactory(f)
	if err2 != nil {
                log.Fatalf("failed to initialize vault service, error: %v", err2)
        }
	vaultServer = vs
	listener, err := net.Listen("unix", cmdArgs.socketFile)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer()
	pb.RegisterKeyManagementServiceServer(s, &server{})
        log.Infof("Version: %s, runtimeName: %s, RuntimeVersion: %s", "v1beta1", "vault", "0.1.0")
        if err := s.Serve(listener); err != nil {
                log.Fatalf("failed to serve: %v", err)
        }   
}
