/*
Copyright 2021 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controlplane_test

import (
	"context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	kauthn "k8s.io/api/authorization/v1"
	rbac "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	. "sigs.k8s.io/controller-runtime/pkg/internal/testing/controlplane"
)

var _ = Describe("Control Plane", func() {
	It("should start and stop successfully with a default etcd & apiserver", func() {
		plane := &ControlPlane{}
		Expect(plane.Start()).To(Succeed())
		Expect(plane.Stop()).To(Succeed())
	})
	It("should use the given etcd & apiserver when starting, if present", func() {
		apiServer := &APIServer{}
		etcd := &Etcd{}
		plane := &ControlPlane{
			APIServer: apiServer,
			Etcd:      etcd,
		}
		Expect(plane.Start()).To(Succeed())
		defer func() { Expect(plane.Stop()).To(Succeed()) }()

		Expect(plane.APIServer).To(BeIdenticalTo(apiServer))
		Expect(plane.Etcd).To(BeIdenticalTo(etcd))
	})

	It("should be able to restart", func() {
		// NB(directxman12): currently restarting invalidates all current users
		// when using CertAuthn.  We need to support restarting as per our previous
		// contract, but it's not clear how much else we actually need to handle, or
		// whether or not this is a safe operation.
		plane := &ControlPlane{}
		Expect(plane.Start()).To(Succeed())
		Expect(plane.Stop()).To(Succeed())
		Expect(plane.Start()).To(Succeed())
		Expect(plane.Stop()).To(Succeed())
	})

	Context("after having started", func() {
		var plane *ControlPlane
		BeforeEach(func() {
			plane = &ControlPlane{}
			Expect(plane.Start()).To(Succeed())
		})
		AfterEach(func() {
			Expect(plane.Stop()).To(Succeed())
		})

		It("should provision a working legacy user and legacy kubectl", func() {
			By("grabbing the legacy kubectl")
			Expect(plane.KubeCtl()).NotTo(BeNil())

			By("grabbing the legacy REST config and testing it")
			cfg, err := plane.RESTClientConfig()
			Expect(err).NotTo(HaveOccurred(), "should be able to grab the legacy REST config")
			cl, err := client.New(cfg, client.Options{})
			Expect(err).NotTo(HaveOccurred(), "should be able to create a client")

			sar := &kauthn.SelfSubjectAccessReview{
				Spec: kauthn.SelfSubjectAccessReviewSpec{
					ResourceAttributes: &kauthn.ResourceAttributes{
						Verb:     "*",
						Group:    "*",
						Version:  "*",
						Resource: "*",
					},
				},
			}
			Expect(cl.Create(context.Background(), sar)).To(Succeed(), "should be able to make a Self-SAR")
			Expect(sar.Status.Allowed).To(BeTrue(), "admin user should be able to do everything")
		})

		// TODO(directxman12): more explicit tests for AddUser -- it's tested indirectly via the
		// legacy user flow, but we should be explicit

		Describe("adding users", func() {
			It("should add new users with different RBAC", func() {

				By("adding a test user")
				user, err := plane.AddUser(User{
					Name:   "test-user",
					Groups: []string{"pod-reader-group"},
				}, nil)
				Expect(err).NotTo(HaveOccurred(), "should be able to add a user")

				By("grabbing the REST config for the new user and testing that it has no permissions")
				cfg := user.Config()
				cl, err := client.New(cfg, client.Options{})
				Expect(err).NotTo(HaveOccurred(), "should be able to create a client")

				sar := &kauthn.SelfSubjectAccessReview{
					Spec: kauthn.SelfSubjectAccessReviewSpec{
						ResourceAttributes: &kauthn.ResourceAttributes{
							Verb:     "*",
							Group:    "*",
							Version:  "*",
							Resource: "*",
						},
					},
				}
				Expect(cl.Create(context.Background(), sar)).Should(Succeed(), "should be able to make a Self-SAR")
				Expect(sar.Status.Allowed).To(BeFalse(), "unconfigured users should not be able to do everything")

				readPod := &kauthn.SelfSubjectAccessReview{
					Spec: kauthn.SelfSubjectAccessReviewSpec{
						ResourceAttributes: &kauthn.ResourceAttributes{
							Verb:     "get",
							Group:    "",
							Version:  "v1",
							Resource: "pods",
						},
					},
				}
				Expect(cl.Create(context.Background(), readPod)).Should(Succeed(), "should be able to make a Self-SAR")
				Expect(readPod.Status.Allowed).To(BeFalse(), "unconfigured users should not be able to read pods")

				By("adding permissions to the new user and verifying it works")
				rootCFG, err := plane.RESTClientConfig()
				Expect(err).NotTo(HaveOccurred(), "should be able to grab the legacy REST config")
				rootClient, err := client.New(rootCFG, client.Options{})
				Expect(err).NotTo(HaveOccurred(), "should be able to create a client")

				podReaderRole := &rbac.ClusterRole{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "pod-reader",
						Namespace: metav1.NamespaceSystem,
					},
					Rules: []rbac.PolicyRule{
						{
							Verbs:     []string{"get"},
							APIGroups: []string{""},
							Resources: []string{"pods"},
						},
					},
				}

				binding := &rbac.ClusterRoleBinding{
					ObjectMeta: metav1.ObjectMeta{
						Name: "pod-reader-binding",
					},
					Subjects: []rbac.Subject{
						{
							Kind: "Group",
							Name: "pod-reader-group",
						},
					},
					RoleRef: rbac.RoleRef{
						APIGroup: "rbac.authorization.k8s.io",
						Name:     "pod-reader",
						Kind:     "ClusterRole",
					},
				}

				Expect(rootClient.Create(context.Background(), podReaderRole)).Should(Succeed(), "should be able to create a pod-reader role")
				Expect(rootClient.Create(context.Background(), binding)).Should(Succeed(), "should be able to create pod-reader role binding")

				readPod2 := &kauthn.SelfSubjectAccessReview{
					Spec: kauthn.SelfSubjectAccessReviewSpec{
						ResourceAttributes: &kauthn.ResourceAttributes{
							Verb:     "get",
							Group:    "",
							Version:  "v1",
							Resource: "pods",
						},
					},
				}

				Expect(cl.Create(context.Background(), readPod2)).Should(Succeed(), "should be able to make a Self-SAR")
				Expect(readPod2.Status.Allowed).To(BeTrue(), "now the new user can read pods!")

			})

			PIt("should be able to provision new users that have a corresponding REST config and & kubectl", func() {

			})

			PIt("should produce a default base REST config if none is given to add", func() {

			})
		})
	})
})
