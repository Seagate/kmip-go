package kmipapi

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"

	"github.com/Seagate/kmip-go"
	"github.com/Seagate/kmip-go/kmip14"
	"github.com/Seagate/kmip-go/ttlv"
	"github.com/google/uuid"
	"k8s.io/klog/v2"
)

const (
	DefaultBufferSize = 4096
)

func BatchCmdGenerateMessage(ctx context.Context, settings *ConfigurationSettings, payload []kmip.RequestBatchItem) (kmip.RequestMessage, error) {
	logger := klog.FromContext(ctx)

	logger.V(4).Info("(1) create batch request message")
	logger.V(5).Info("send batch request message", "CurrentProtocolVersionMajor", settings.ProtocolVersionMajor, "CurrentProtocolVersionMinor", settings.ProtocolVersionMinor)

	BatchNum := len(payload)
	msg := kmip.RequestMessage{
		RequestHeader: kmip.RequestHeader{
			ProtocolVersion: kmip.ProtocolVersion{
				ProtocolVersionMajor: settings.ProtocolVersionMajor,
				ProtocolVersionMinor: settings.ProtocolVersionMinor,
			},
			BatchCount:       BatchNum,
			BatchOrderOption: true,
		},
		BatchItem: payload,
	}
	return msg, nil
}

// SendRequestMessage: Send a KMIP request message
func SendRequestMessage(ctx context.Context, connection *tls.Conn, settings *ConfigurationSettings, operation uint32, payload interface{}, dobatch bool) (*ttlv.Decoder, *kmip.ResponseBatchItem, error) {
	logger := klog.FromContext(ctx)
	biID := uuid.New()

	var kmipreq []byte
	var err error
	// var msg kmip.RequestMessage

	if dobatch == true {
		kmipreq, err = ttlv.Marshal(payload)
		if err != nil {
			return nil, nil, fmt.Errorf("dobatch - failed to marshal message, error: %v", err)
		}
	} else {
		logger.V(4).Info("(1) create request message")
		logger.V(5).Info("send request message", "CurrentProtocolVersionMajor", settings.ProtocolVersionMajor, "CurrentProtocolVersionMinor", settings.ProtocolVersionMinor)

		msg := kmip.RequestMessage{
			RequestHeader: kmip.RequestHeader{
				ProtocolVersion: kmip.ProtocolVersion{
					ProtocolVersionMajor: settings.ProtocolVersionMajor,
					ProtocolVersionMinor: settings.ProtocolVersionMinor,
				},
				BatchCount:       1,
				BatchOrderOption: true,
			},
			BatchItem: []kmip.RequestBatchItem{
				{
					UniqueBatchItemID: biID[:],
					Operation:         kmip14.Operation(operation),
					RequestPayload:    payload,
				},
			},
		}

		logger.V(4).Info("(2) marshal message and print request")
		kmipreq, err = ttlv.Marshal(msg)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal message, error: %v", err)
		}
	}
	logger.V(5).Info("KMIP message", "request", kmipreq)

	if connection != nil {

		logger.V(4).Info("(3) write message")
		_, err = connection.Write(kmipreq)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to write message, error: %v", err)
		}

		logger.V(4).Info("(4) read response 1")
		buf := make([]byte, DefaultBufferSize)
		_, err = bufio.NewReader(connection).Read(buf)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read buffer from response, error: %v", err)
		}

		logger.V(4).Info("(5) extract response from TTLV buffer")
		resp := ttlv.TTLV(buf)
		logger.V(5).Info("ttlv", "response", resp)

		// Create a TTLV decoder from a new reader
		decoder := ttlv.NewDecoder(bytes.NewReader(resp))
		if decoder == nil {
			return nil, nil, fmt.Errorf("failed to create decoder, error: nil")
		}

		// Extract the KMIP response message
		var respMsg kmip.ResponseMessage
		err = decoder.DecodeValue(&respMsg, resp)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode response message, error: %v", err)
		}

		logger.V(4).Info("(6) extract batch item from response message", "BatchCount", respMsg.ResponseHeader.BatchCount)
		logger.V(5).Info("response", "message", respMsg)
		if len(respMsg.BatchItem) == 0 {
			return nil, nil, fmt.Errorf("response message had not batch items")
		}

		// Check the status of the each batch item
		i := respMsg.ResponseHeader.BatchCount - 1
		for j := 0; j <= i; j++ {
			if respMsg.ResponseHeader.BatchCount >= 0 {
				if respMsg.BatchItem[j].ResultStatus != kmip14.ResultStatusSuccess {
					logger.V(4).Info("send message results", "ResultStatus", respMsg.BatchItem[j].ResultStatus, "ResultReason",
						respMsg.BatchItem[j].ResultReason, "ResultMessage", respMsg.BatchItem[j].ResultMessage)
					return nil, nil, fmt.Errorf("send operation (%d) status (%s) reason (%s) message (%s)",
						operation, respMsg.BatchItem[j].ResultStatus, respMsg.BatchItem[j].ResultReason, respMsg.BatchItem[j].ResultMessage)
				}
			}
		}

		if respMsg.ResponseHeader.BatchCount >= 0 && respMsg.BatchItem[i].ResultStatus == kmip14.ResultStatusSuccess {
			logger.V(4).Info("(7) returning decoder and the first batch item", "items", len(respMsg.BatchItem))
			return decoder, &respMsg.BatchItem[i], nil
		} else {
			return nil, nil, fmt.Errorf(
				"server status (%s) reason (%s) message (%s)",
				respMsg.BatchItem[i].ResultStatus, respMsg.BatchItem[i].ResultReason, respMsg.BatchItem[i].ResultMessage)
		}

	} else {
		return nil, nil, fmt.Errorf("TLS connection is <nil>")
	}
}
