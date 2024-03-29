package stubs

// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import (
	"context"

	"cloud.google.com/go/storage"
)

// StorageStub provides a stub for the Storage client.
type StorageStub struct {
	service            *storage.Client
	RemovedBucketUsers storage.ACLEntity
}

// RemoveBucketUsers removes the users from the given bucket.
func (s *StorageStub) RemoveBucketUsers(ctx context.Context, bucketName string, entity storage.ACLEntity) error {
	s.RemovedBucketUsers = entity
	return nil
}
